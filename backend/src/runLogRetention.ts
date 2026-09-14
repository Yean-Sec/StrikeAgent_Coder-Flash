import db from './db';
import { getSetting } from './settings';

/**
 * project_run_logs（Pi Agent 原始 stdout/stderr）保留与清理。
 *
 * 背景：该表可膨胀到数十 GB / 数千万行。better-sqlite3 是同步的——长事务或
 * wal_checkpoint(TRUNCATE) 会堵住 Node 事件循环，让所有 /api/* 一起超时，
 * 前端表现为「无法连接后端」与永久加载骨架。
 *
 * 策略：
 *  - 每个项目只保留最近 keepRuns 个 run 的完整日志（其余 run 一律可删）；
 *  - 若 keepRuns=0，则退化为按 keepDays 时间窗口删除；
 *  - 正在运行/排队的项目跳过；
 *  - 候选项目从 projects 表枚举（O(项目数)），绝不对千万行做 DISTINCT/GROUP BY；
 *  - 运行时清道夫走异步路径：每批/每项目后 setImmediate 让出事件循环；
 *  - 运行时只用 PASSIVE checkpoint，不做 TRUNCATE。
 */

export interface RunLogPruneOptions {
  keepDays?: number;
  keepRunsPerProject?: number;
  isProtected?: (projectId: string) => boolean;
  /** 单批删除行数。运行时宜小（默认异步路径 400）。 */
  batchSize?: number;
  /** 本次总删除上限。 */
  maxDeletes?: number;
  /** 本次最多扫描多少个项目（轮转）。 */
  maxProjects?: number;
  /** 轮转起点（项目 id）。 */
  cursor?: string | null;
  /**
   * 协作回调：每删完一批后调用。异步清道夫传入 `await yield`；
   * 同步维护脚本不传，整轮阻塞执行。
   */
  afterBatch?: () => void | Promise<void>;
}

export interface RunLogPruneResult {
  deleted: number;
  projectsAffected: number;
  projectsScanned: number;
  nextCursor: string | null;
}

function resolveRetention(opts: RunLogPruneOptions): { keepDays: number; keepRuns: number } {
  const rawDays = opts.keepDays ?? Number(getSetting('run_log_keep_days') || 0);
  const rawRuns =
    opts.keepRunsPerProject ?? Number(getSetting('run_log_keep_runs_per_project') || 0);
  return {
    keepDays: Number.isFinite(rawDays) && rawDays > 0 ? rawDays : 0,
    keepRuns: Number.isFinite(rawRuns) && rawRuns > 0 ? Math.floor(rawRuns) : 0,
  };
}

function dbActiveProjectIds(): Set<string> {
  const rows = db
    .prepare(
      `SELECT id FROM projects
       WHERE status IN ('running','queued') OR verify_status IN ('running','queued')`
    )
    .all() as { id: string }[];
  return new Set(rows.map((r) => r.id));
}

function listPruneCandidateIds(cursor: string | null | undefined): string[] {
  if (cursor) {
    return (
      db
        .prepare(`SELECT id FROM projects WHERE id > ? ORDER BY id ASC`)
        .all(cursor) as { id: string }[]
    ).map((r) => r.id);
  }
  return (db.prepare(`SELECT id FROM projects ORDER BY id ASC`).all() as { id: string }[]).map(
    (r) => r.id
  );
}

async function pruneRunLogsCore(opts: RunLogPruneOptions): Promise<RunLogPruneResult> {
  const { keepDays, keepRuns } = resolveRetention(opts);
  const batchSize = opts.batchSize && opts.batchSize > 0 ? Math.floor(opts.batchSize) : 500;
  const maxDeletes =
    opts.maxDeletes && opts.maxDeletes > 0 ? Math.floor(opts.maxDeletes) : Number.POSITIVE_INFINITY;
  const maxProjects =
    opts.maxProjects && opts.maxProjects > 0 ? Math.floor(opts.maxProjects) : Number.POSITIVE_INFINITY;
  const cutoff = keepDays > 0 ? Date.now() - keepDays * 86_400_000 : Date.now();
  const dbActive = dbActiveProjectIds();
  const afterBatch = opts.afterBatch;

  // 不用 GROUP BY 全表聚合（千万行项目上可卡数秒）：按 ts 倒序取最近若干行，在 JS 侧去重拿最近 N 个 run。
  const recentRunsStmt = db.prepare(
    `SELECT run_id FROM project_run_logs WHERE project_id = ? ORDER BY ts DESC LIMIT ?`
  );

  let deleted = 0;
  let projectsAffected = 0;
  let projectsScanned = 0;
  let nextCursor: string | null = null;

  const recentKeepRunIds = (id: string): string[] => {
    if (keepRuns <= 0) return [];
    const rows = recentRunsStmt.all(id, Math.max(keepRuns * 80, 200)) as { run_id: string }[];
    const out: string[] = [];
    const seen = new Set<string>();
    for (const row of rows) {
      if (seen.has(row.run_id)) continue;
      seen.add(row.run_id);
      out.push(row.run_id);
      if (out.length >= keepRuns) break;
    }
    return out;
  };

  const processId = async (id: string): Promise<'ok' | 'budget'> => {
    if (deleted >= maxDeletes) return 'budget';
    if (dbActive.has(id)) return 'ok';
    if (opts.isProtected && opts.isProtected(id)) return 'ok';

    projectsScanned++;
    const keepRunIds = recentKeepRunIds(id);
    // keepRuns>0：只留最近 N 个 run（这是消化 18GB 膨胀的主力）。
    // keepRuns=0：退化为按 keepDays 删超期行。
    const selectRowids =
      keepRunIds.length > 0
        ? db.prepare(
            `SELECT rowid FROM project_run_logs
             WHERE project_id = ? AND run_id NOT IN (${keepRunIds.map(() => '?').join(',')})
             LIMIT ?`
          )
        : db.prepare(
            `SELECT rowid FROM project_run_logs
             WHERE project_id = ? AND ts < ?
             LIMIT ?`
          );

    let projectDeleted = 0;
    for (;;) {
      if (deleted >= maxDeletes) break;
      const budget = Math.min(batchSize, maxDeletes - deleted);
      const rows =
        keepRunIds.length > 0
          ? (selectRowids.all(id, ...keepRunIds, budget) as { rowid: number }[])
          : (selectRowids.all(id, cutoff, budget) as { rowid: number }[]);
      if (rows.length === 0) break;
      const ids = rows.map((r) => r.rowid);
      const changed = db
        .prepare(`DELETE FROM project_run_logs WHERE rowid IN (${ids.map(() => '?').join(',')})`)
        .run(...ids).changes;
      deleted += changed;
      projectDeleted += changed;
      if (afterBatch) await afterBatch();
      if (rows.length < budget) break;
    }
    if (projectDeleted > 0) projectsAffected++;
    return deleted >= maxDeletes ? 'budget' : 'ok';
  };

  const scan = async (ids: string[], stopAfterId?: string): Promise<boolean> => {
    // 返回 true = 因预算/项目上限停下（nextCursor 已设）；false = 扫完
    for (const id of ids) {
      if (stopAfterId && id > stopAfterId) return false;
      if (projectsScanned >= maxProjects || deleted >= maxDeletes) {
        nextCursor = id;
        return true;
      }
      const status = await processId(id);
      if (status === 'budget') {
        nextCursor = id;
        return true;
      }
      if (afterBatch) await afterBatch();
    }
    return false;
  };

  const primary = listPruneCandidateIds(opts.cursor);
  const stopped = await scan(primary);
  // 带着 cursor 扫到末尾且还有预算：从开头补扫到原 cursor，形成轮转。
  if (!stopped && opts.cursor && deleted < maxDeletes && projectsScanned < maxProjects) {
    const head = listPruneCandidateIds(null);
    await scan(head, opts.cursor);
  }

  return { deleted, projectsAffected, projectsScanned, nextCursor };
}

/** 同步清理（维护脚本）。整轮占用事件循环——勿在运行时定时器里调用。 */
export function pruneRunLogs(opts: RunLogPruneOptions = {}): RunLogPruneResult {
  return pruneRunLogsSync(opts);
}

/** 真正的同步实现，供维护脚本使用。 */
function pruneRunLogsSync(opts: RunLogPruneOptions): RunLogPruneResult {
  const { keepDays, keepRuns } = resolveRetention(opts);
  const batchSize = opts.batchSize && opts.batchSize > 0 ? Math.floor(opts.batchSize) : 2000;
  const maxDeletes =
    opts.maxDeletes && opts.maxDeletes > 0 ? Math.floor(opts.maxDeletes) : Number.POSITIVE_INFINITY;
  const maxProjects =
    opts.maxProjects && opts.maxProjects > 0 ? Math.floor(opts.maxProjects) : Number.POSITIVE_INFINITY;
  const cutoff = keepDays > 0 ? Date.now() - keepDays * 86_400_000 : Date.now();
  const dbActive = dbActiveProjectIds();
  const recentRunsStmt = db.prepare(
    `SELECT run_id FROM project_run_logs WHERE project_id = ? ORDER BY ts DESC LIMIT ?`
  );

  let deleted = 0;
  let projectsAffected = 0;
  let projectsScanned = 0;
  let nextCursor: string | null = null;
  const projectIds = listPruneCandidateIds(opts.cursor);

  for (const id of projectIds) {
    if (projectsScanned >= maxProjects || deleted >= maxDeletes) {
      nextCursor = id;
      break;
    }
    if (dbActive.has(id)) continue;
    if (opts.isProtected && opts.isProtected(id)) continue;
    projectsScanned++;

    const keepRunIds: string[] = [];
    if (keepRuns > 0) {
      const rows = recentRunsStmt.all(id, Math.max(keepRuns * 80, 200)) as { run_id: string }[];
      const seen = new Set<string>();
      for (const row of rows) {
        if (seen.has(row.run_id)) continue;
        seen.add(row.run_id);
        keepRunIds.push(row.run_id);
        if (keepRunIds.length >= keepRuns) break;
      }
    }
    const selectRowids =
      keepRunIds.length > 0
        ? db.prepare(
            `SELECT rowid FROM project_run_logs
             WHERE project_id = ? AND run_id NOT IN (${keepRunIds.map(() => '?').join(',')})
             LIMIT ?`
          )
        : db.prepare(
            `SELECT rowid FROM project_run_logs
             WHERE project_id = ? AND ts < ?
             LIMIT ?`
          );

    let projectDeleted = 0;
    for (;;) {
      if (deleted >= maxDeletes) break;
      const budget = Math.min(batchSize, maxDeletes - deleted);
      const rows =
        keepRunIds.length > 0
          ? (selectRowids.all(id, ...keepRunIds, budget) as { rowid: number }[])
          : (selectRowids.all(id, cutoff, budget) as { rowid: number }[]);
      if (rows.length === 0) break;
      const ids = rows.map((r) => r.rowid);
      const changed = db
        .prepare(`DELETE FROM project_run_logs WHERE rowid IN (${ids.map(() => '?').join(',')})`)
        .run(...ids).changes;
      deleted += changed;
      projectDeleted += changed;
      if (rows.length < budget) break;
    }
    if (projectDeleted > 0) projectsAffected++;
  }

  return { deleted, projectsAffected, projectsScanned, nextCursor };
}

/** 协作式异步清理：每批删除后让出事件循环，供 /api/* 插队。 */
export function pruneRunLogsAsync(opts: RunLogPruneOptions = {}): Promise<RunLogPruneResult> {
  return pruneRunLogsCore({
    batchSize: 400,
    maxDeletes: 60_000,
    maxProjects: 80,
    ...opts,
    afterBatch: () => new Promise<void>((r) => setImmediate(r)),
  });
}

/**
 * 【维护脚本专用·同步】把已有超限的 run 回溯裁剪到最多保留最近 cap 行（按 seq 保留最新的）。
 * 面向历史膨胀：写入端的行数封顶只约束新数据，存量里那些 40 万行的 run 需要这里回收。
 * 逐项目做 per-project GROUP BY（走 idx_run_log_project_ts，离线单次可接受），再分批删最老的行。
 * 整轮阻塞事件循环——仅供离线维护脚本调用，勿放进运行时定时器。
 */
export function trimOversizedRunsSync(
  cap?: number,
  batchSize = 5000
): { deleted: number; runsTrimmed: number; projectsScanned: number } {
  const rowCap =
    cap && cap > 0
      ? Math.floor(cap)
      : Math.floor(Number(getSetting('run_log_max_rows_per_run') || 0));
  if (!Number.isFinite(rowCap) || rowCap <= 0) {
    return { deleted: 0, runsTrimmed: 0, projectsScanned: 0 };
  }
  const projectIds = (
    db.prepare('SELECT id FROM projects ORDER BY id ASC').all() as { id: string }[]
  ).map((r) => r.id);
  const oversizedRunsStmt = db.prepare(
    `SELECT run_id, COUNT(*) AS c FROM project_run_logs
     WHERE project_id = ? GROUP BY run_id HAVING c > ?`
  );
  const delOldestStmt = db.prepare(
    `DELETE FROM project_run_logs
     WHERE rowid IN (
       SELECT rowid FROM project_run_logs WHERE run_id = ? ORDER BY seq ASC LIMIT ?
     )`
  );

  let deleted = 0;
  let runsTrimmed = 0;
  let projectsScanned = 0;
  for (const pid of projectIds) {
    projectsScanned++;
    const runs = oversizedRunsStmt.all(pid, rowCap) as { run_id: string; c: number }[];
    for (const run of runs) {
      let toDelete = run.c - rowCap;
      if (toDelete <= 0) continue;
      runsTrimmed++;
      while (toDelete > 0) {
        const n = Math.min(batchSize, toDelete);
        const changed = delOldestStmt.run(run.run_id, n).changes;
        deleted += changed;
        toDelete -= n;
        if (changed < n) break;
      }
    }
  }
  return { deleted, runsTrimmed, projectsScanned };
}

export type CheckpointMode = 'truncate' | 'passive' | 'none';

/**
 * WAL checkpoint。
 * - truncate：阻塞重，仅维护脚本使用
 * - passive：不抢写锁，运行时清道夫使用
 * - none：跳过
 */
export function checkpointAndReclaim(vacuum = false, mode: CheckpointMode = 'truncate'): void {
  if (mode === 'none') return;
  try {
    if (mode === 'passive') {
      db.pragma('wal_checkpoint(PASSIVE)');
    } else {
      db.pragma('wal_checkpoint(TRUNCATE)');
    }
  } catch (error) {
    console.error('[code] wal_checkpoint 失败', error);
  }
  if (vacuum) {
    try {
      db.exec('VACUUM');
    } catch (error) {
      console.error('[code] VACUUM 失败', error);
    }
  }
}
