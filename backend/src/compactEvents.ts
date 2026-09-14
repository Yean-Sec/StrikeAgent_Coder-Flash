import db from './db';
import { archiveInactiveProjects } from './eventArchive';
import { pruneRunLogs, trimOversizedRunsSync } from './runLogRetention';

async function main(): Promise<void> {
  const active = (
    db
      .prepare(
        `SELECT COUNT(*) AS c FROM projects
         WHERE status IN ('running','queued') OR verify_status IN ('running','queued')`
      )
      .get() as { c: number }
  ).c;
  if (active > 0) {
    throw new Error(
      `仍有 ${active} 个审计/验证任务处于运行或排队状态。请先停止后端与任务，再执行日志压缩维护。`
    );
  }

  let projects = 0;
  let archived = 0;
  let deleted = 0;
  for (;;) {
    const batch = await archiveInactiveProjects({ maxProjects: 10, minEvents: 801, keepRecent: 800 });
    if (batch.length === 0) break;
    projects += batch.length;
    archived += batch.reduce((sum, item) => sum + item.archived, 0);
    deleted += batch.reduce((sum, item) => sum + item.deleted, 0);
    console.log(
      `[event-maintenance] 已处理 ${projects} 个项目，归档 ${archived} 条，数据库清理 ${deleted} 条`
    );
    if (batch.every((item) => item.deleted === 0)) break;
  }

  // 运行日志（project_run_logs）一次性回收：按保留策略删除超期日志（脚本已确保无运行中任务，
  // 故按 DB 状态即可，正在运行/排队项目本就不存在）。这是把库从数 GB 降回来的主力。
  console.log('[event-maintenance] 开始按保留策略清理 project_run_logs…');
  const runLog = pruneRunLogs();
  console.log(
    `[event-maintenance] 运行日志清理完成：删除 ${runLog.deleted} 条，涉及 ${runLog.projectsAffected}/${runLog.projectsScanned} 个项目`
  );

  // 回溯裁剪：保留下来的 run 里仍可能有失控的超大 run（历史上 40 万行/run），
  // 按 run_log_max_rows_per_run 把它们裁到最近 N 行——这是把存量 6.3GB 真正降下来的关键一步。
  console.log('[event-maintenance] 开始回溯裁剪超限 run（run_log_max_rows_per_run）…');
  const trim = trimOversizedRunsSync();
  console.log(
    `[event-maintenance] 超限 run 裁剪完成：删除 ${trim.deleted} 条，裁剪 ${trim.runsTrimmed} 个 run（扫 ${trim.projectsScanned} 项）`
  );

  console.log('[event-maintenance] 归档校验完成，开始 WAL checkpoint 与 VACUUM…');
  db.pragma('wal_checkpoint(TRUNCATE)');
  db.exec('VACUUM');
  console.log(
    `[event-maintenance] 完成：项目 ${projects}，归档事件 ${archived}，清理事件 ${deleted}，清理运行日志 ${runLog.deleted}`
  );
}

main().catch((error) => {
  console.error('[event-maintenance] 失败：', error?.message || error);
  process.exitCode = 1;
});
