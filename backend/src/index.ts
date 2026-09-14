import express from 'express';
import cors from 'cors';
import compression from 'compression';
import http from 'http';
import fs from 'fs';
import path from 'path';
import db from './db';
import routes from './routes';
import { initWebSocket } from './ws';
import { initSettings, getSetting, setSetting } from './settings';
import { startMonitorScheduler } from './monitor';
import {
  enqueueAudit,
  enqueueVerify,
  resumeProject,
  markStartupOrphansPaused,
  reconcileEnvAndContainers,
  startEnvReconcileScheduler,
  recoverEnvFalseFailures,
  reconcileFalseCompletedVerify,
  resumeIncompleteVerifyProjects,
  recoverMispausedAudits,
  reconcileMispausedCompletedAudits,
  sweepOrphanWorkspaces,
  startWorkspaceJanitor,
  startRunLogJanitor,
  startAuditStallWatchdog,
  harvestIdleProjectSources,
  syncVerifiedFlags,
  syncFrontendRce,
  reingestAllStaleFromDiskAsync,
  recoverPendingVerifyOneJobs,
  requeueStaleEnvPrebuilds,
} from './runner';
import { versionFromName, systemNameFromName, repoNameFromUrl, placeholderLabel } from './util';
import { applySeverityPolicy, realTeamLabel } from './severityPolicy';
import { invalidateProjectStatusReads, invalidateVulnerabilityReads } from './readCache';
import type { Severity } from './types';
import { backfillVerificationItemsFromReports } from './verificationStore';
import { startEventArchiveScheduler } from './eventArchive';
import { backfillExistingLogsToSqlite } from './logRetention';

const PORT = Number(process.env.PORT || 8787);
const BIND_HOST = process.env.BIND_HOST || '127.0.0.1';

// 全局兜底：避免长时间重型审计中偶发的未捕获异常/拒绝直接杀死服务进程
process.on('uncaughtException', (err) => {
  console.error('[uncaughtException]', err);
});
process.on('unhandledRejection', (reason) => {
  console.error('[unhandledRejection]', reason);
});

initSettings();

// 一次性回填：历史项目的版本号 / 系统名为空时，智能解析补上（不覆盖已有值）。
try {
  const rows = db
    .prepare(
      "SELECT id, archive_name, source_type, source_ref, source_version, system_name FROM projects"
    )
    .all() as {
    id: string;
    archive_name: string;
    source_type: string;
    source_ref: string;
    source_version: string | null;
    system_name: string | null;
  }[];
  const updVer = db.prepare('UPDATE projects SET source_version = ? WHERE id = ?');
  const updSys = db.prepare('UPDATE projects SET system_name = ? WHERE id = ?');
  let filledVer = 0;
  let filledSys = 0;
  for (const r of rows) {
    const isGithub = r.source_type === 'github';
    if (!r.source_version) {
      // github 版本号交给 clone 后的 resolveProjectVersion，这里只回填压缩包来源
      const v = isGithub ? null : versionFromName(r.archive_name);
      if (v) {
        updVer.run(v, r.id);
        filledVer++;
      }
    }
    if (!r.system_name) {
      const sys =
        (isGithub
          ? repoNameFromUrl(r.source_ref)
          : systemNameFromName(r.archive_name)) ?? placeholderLabel('系统');
      updSys.run(sys, r.id);
      filledSys++;
    }
  }
  if (filledVer > 0 || filledSys > 0)
    console.log(
      `[code] 已回填版本号 ${filledVer} 个、系统名 ${filledSys} 个`
    );
} catch (e) {
  console.error('[code] 版本号/系统名回填失败', e);
}

// 一次性回填：为存量项目回填 vulnerabilities.verified 持久化列（此后由 runner 增量维护）。
try {
  if (getSetting('verified_backfill_v1') !== '1') {
    const rows = db
      .prepare("SELECT id FROM projects WHERE exploit_report IS NOT NULL")
      .all() as { id: string }[];
    for (const r of rows) syncVerifiedFlags(r.id);
    setSetting('verified_backfill_v1', '1');
    if (rows.length > 0)
      console.log(`[code] 已回填 ${rows.length} 个项目的漏洞验证标记(verified)`);
  }
} catch (e) {
  console.error('[code] verified 列回填失败', e);
}

// 一次性迁移：把历史 exploit_report 转成按 vulnerability_id 持久化的权威远程验证项，
// 并按严格远程成功口径重算 verified（代码确认但远程不可达不再算成功）。
try {
  if (getSetting('verification_items_backfill_v1') !== '1') {
    const result = backfillVerificationItemsFromReports();
    setSetting('verification_items_backfill_v1', '1');
    invalidateVulnerabilityReads();
    if (result.projects > 0) {
      console.log(
        `[code] 已回填 ${result.projects} 个项目的 ${result.items} 条权威验证项，并按远程实测口径重算 verified`
      );
    }
  }
} catch (e) {
  console.error('[code] 权威验证项回填失败', e);
}

try {
  if (getSetting('frontend_rce_v3') !== '1') {
    const rows = db
      .prepare('SELECT id FROM projects WHERE exploit_report IS NOT NULL')
      .all() as { id: string }[];
    for (const r of rows) syncFrontendRce(r.id);
    setSetting('frontend_rce_v3', '1');
    if (rows.length > 0)
      console.log(
        `[code] 已回填 ${rows.length} 个项目的前台 RCE 标记(远程验证 RCE · none/user)`
      );
  }
} catch (e) {
  console.error('[code] frontend_rce 列回填失败', e);
}

// 一次性：判据收紧 + 新增 frontend_rce_at 后，对有 exploit_report 的项目重跑 syncFrontendRce，
// 既按新判据刷新 frontend_rce 标记，又用项目 verify_finished_at 回填「拿到前台 RCE 的时间」。
try {
  if (getSetting('frontend_rce_at_v1') !== '1') {
    const rows = db
      .prepare('SELECT id FROM projects WHERE exploit_report IS NOT NULL')
      .all() as { id: string }[];
    for (const r of rows) syncFrontendRce(r.id);
    setSetting('frontend_rce_at_v1', '1');
    if (rows.length > 0)
      console.log(
        `[code] 已按收紧判据刷新前台 RCE 并回填获得时间(frontend_rce_at)，涉及 ${rows.length} 个项目`
      );
  }
} catch (e) {
  console.error('[code] frontend_rce_at 回填失败', e);
}

// 一次性：收紧 RCE 标题判定（排除源码路径 .php 误触、XSS 挂模板注入文案）后全量重算。
try {
  if (getSetting('frontend_rce_v4') !== '1') {
    const rows = db
      .prepare('SELECT id FROM projects WHERE exploit_report IS NOT NULL')
      .all() as { id: string }[];
    for (const r of rows) syncFrontendRce(r.id);
    setSetting('frontend_rce_v4', '1');
    if (rows.length > 0)
      console.log(
        `[code] 已按 v4 标题判据刷新前台 RCE（剔除 .php 路径/XSS 误标），涉及 ${rows.length} 个项目`
      );
  }
} catch (e) {
  console.error('[code] frontend_rce_v4 回填失败', e);
}

// 一次性：修复 isStrictHttpRemoteVerified 的 HTTP 交互识别过严问题——
// 时间盲注/侧信道（$(sleep N) + 耗时对比）与中文「HTTP请求/响应」措辞此前被误判为
// "仅代码分析"而漏标，现放行后对存量项目全量重算。
try {
  if (getSetting('frontend_rce_v5') !== '1') {
    const rows = db
      .prepare('SELECT id FROM projects WHERE exploit_report IS NOT NULL')
      .all() as { id: string }[];
    for (const r of rows) syncFrontendRce(r.id);
    setSetting('frontend_rce_v5', '1');
    if (rows.length > 0)
      console.log(
        `[code] 已按 v5 判据修复时间盲注/中文HTTP措辞漏判，重算 ${rows.length} 个项目的前台 RCE`
      );
  }
} catch (e) {
  console.error('[code] frontend_rce_v5 回填失败', e);
}

// 一次性：successSignal 补充"成功实现/完成/复现...RCE"等词序变体，修复与 v5 同批的漏判。
try {
  if (getSetting('frontend_rce_v6') !== '1') {
    const rows = db
      .prepare('SELECT id FROM projects WHERE exploit_report IS NOT NULL')
      .all() as { id: string }[];
    for (const r of rows) syncFrontendRce(r.id);
    setSetting('frontend_rce_v6', '1');
    if (rows.length > 0)
      console.log(
        `[code] 已按 v6 判据修复"成功实现RCE"等措辞漏判，重算 ${rows.length} 个项目的前台 RCE`
      );
  }
} catch (e) {
  console.error('[code] frontend_rce_v6 回填失败', e);
}

// 一次性重封顶：对存量漏洞重跑 applySeverityPolicy，把新增/加强的低价值降级规则
// （令牌永不过期、传输未加密、CORS 过宽、缺安全响应头等）应用到历史数据上。
// 策略只降不升、幂等，因此安全；仅对被封顶的漏洞回写等级并重算所在项目的 count_*。
try {
  if (getSetting('severity_recap_v1') !== '1') {
    type RecapRow = {
      id: string;
      project_id: string;
      title: string;
      category: string;
      description: string;
      recommendation: string;
      code_snippet: string;
      taint_chain: string;
      auth_required: string | null;
      severity: string;
      severity_original: string | null;
      regrade_reason: string | null;
    };
    const rows = db
      .prepare(
        `SELECT id, project_id, title, category, description, recommendation, code_snippet,
                taint_chain, auth_required, severity, severity_original, regrade_reason
         FROM vulnerabilities`
      )
      .all() as RecapRow[];
    const updateStmt = db.prepare(
      `UPDATE vulnerabilities
         SET severity = ?, severity_original = ?, regrade_value = ?, regrade_reason = ?
       WHERE id = ?`
    );
    const projCountStmt = db.prepare(
      `UPDATE projects SET count_critical=?, count_high=?, count_medium=?, count_low=?, count_info=? WHERE id=?`
    );
    type Counts = Record<Severity, number>;
    const newCounts = new Map<string, Counts>();
    const ensure = (pid: string): Counts => {
      let c = newCounts.get(pid);
      if (!c) {
        c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        newCounts.set(pid, c);
      }
      return c;
    };
    const affectedProjects = new Set<string>();
    let changedRows = 0;
    const tx = db.transaction(() => {
      for (const r of rows) {
        const res = applySeverityPolicy(r);
        ensure(r.project_id)[res.severity]++;
        if (res.changed) {
          changedRows++;
          affectedProjects.add(r.project_id);
          updateStmt.run(
            res.severity,
            res.severityOriginal,
            realTeamLabel(res.severity),
            res.regradeReason,
            r.id
          );
        }
      }
      // 仅对确有漏洞被封顶的项目重算 count_*（其它项目计数不受影响）。
      for (const pid of affectedProjects) {
        const c = newCounts.get(pid)!;
        projCountStmt.run(c.critical, c.high, c.medium, c.low, c.info, pid);
      }
    });
    tx();
    setSetting('severity_recap_v1', '1');
    if (changedRows > 0) {
      invalidateVulnerabilityReads();
      invalidateProjectStatusReads();
      console.log(
        `[code] 严重度重封顶完成：${changedRows} 条漏洞按新降级规则下调，涉及 ${affectedProjects.size} 个项目`
      );
    }
  }
} catch (e) {
  console.error('[code] 严重度重封顶回填失败', e);
}

// 一次性清理：早期版本把结构化污点链数组直接 String() 写库，退化成
// "[object Object],[object Object],…" 存进 taint_chain，导致漏洞详情页显示乱码。
// 此后写入路径已改用 normalizeTaintChain 规范化，这里只需清空历史脏数据一次。
try {
  if (getSetting('taint_chain_corruption_backfill_v1') !== '1') {
    const r = db
      .prepare("UPDATE vulnerabilities SET taint_chain = '' WHERE taint_chain LIKE '%[object Object]%'")
      .run();
    setSetting('taint_chain_corruption_backfill_v1', '1');
    if (r.changes > 0)
      console.log(`[code] 已清理 ${r.changes} 条被污染的污点链(taint_chain)记录`);
  }
} catch (e) {
  console.error('[code] taint_chain 污染数据清理失败', e);
}

/**
 * 启动时处理上次残留的 running/queued 任务。
 * 默认（auto_resume_orphans_on_startup≠'1'）：只标为 paused，不 spawn Pi——
 * 避免杀进程/重启后端后再次批量拉起孤儿审计。需要自动续跑时在设置中开启该开关。
 * 注意：此函数【只能在成功监听端口后调用】——否则抢不到端口的重复实例也会 enqueue。
 */
function recoverOrphans(): void {
  const auditOrphans = db
    .prepare("SELECT id FROM projects WHERE status IN ('running','queued')")
    .all() as { id: string }[];
  const verifyOrphans = db
    .prepare(
      `SELECT id, status FROM projects
       WHERE verify_status IN ('running','queued')
         AND NOT EXISTS (
           SELECT 1 FROM vulnerability_verifications vv
           WHERE vv.project_id = projects.id AND vv.state IN ('queued','running')
         )`
    )
    .all() as { id: string; status: string }[];

  // 走 setAuditStatus/setVerifyStatus，保证广播 project_status（裸 SQL 不会通知前端，页面会假显示「审计中」）。
  markStartupOrphansPaused(
    auditOrphans.map((r) => r.id),
    verifyOrphans.map((r) => r.id)
  );

  // 靶机搭建是独立 Pi：审计被标暂停后，仍恢复已选完整靶机的搭建通道
  try {
    const envN = requeueStaleEnvPrebuilds();
    if (envN > 0) {
      console.log(`[code] 已为 ${envN} 个项目恢复独立靶机搭建（不受审计暂停影响）`);
    }
  } catch (e) {
    console.error('[code] 独立靶机搭建恢复失败', e);
  }

  const autoResume =
    getSetting('auto_resume_orphans_on_startup') === '1' && getSetting('claude_jobs_enabled') !== '0';
  const total = auditOrphans.length + verifyOrphans.length;

  // 延迟到下一个事件循环再入队，确保 runner 等模块完成初始化
  setTimeout(() => {
    if (!autoResume) {
      // 一次性迁移标记仍推进，避免以后误把「未完成验证」当成新库再偷偷批量入队
      if (getSetting('verify_pending_resume_v2') !== '1') {
        setSetting('verify_pending_resume_v2', '1');
      }
      if (getSetting('mispaused_audit_recovery_v1') !== '1') {
        setSetting('mispaused_audit_recovery_v1', '1');
      }
      setTimeout(() => {
        try {
          const fixed = reconcileMispausedCompletedAudits();
          if (fixed > 0) {
            console.log(`[code] 已按完成态动态校正 ${fixed} 个项目（完成↔中途暂停）`);
          }
        } catch (e) {
          console.error('[code] 完成态动态校正失败', e);
        }
      }, 3000);
      if (total > 0) {
        console.log(
          `[code] 已将 ${total} 个中断任务标为暂停（未自动续跑；设置 auto_resume_orphans_on_startup=1 可恢复启动续跑）`
        );
      }
      return;
    }

    if (getSetting('verify_pending_resume_v2') !== '1') {
      const resumed = resumeIncompleteVerifyProjects();
      setSetting('verify_pending_resume_v2', '1');
      if (resumed > 0) {
        console.log(`[code] 已为 ${resumed} 个未完成验证的项目排队续跑`);
      }
    }
    // 审计中断 → 走 resumeProject「智能续跑」：若磁盘 JSON/ 已有子智能体发现，补全缺失子智能体
    // 并执行与全量审计相同的后半段；确无产物才从头审。
    let auditResumeOk = 0;
    for (const r of auditOrphans) {
      if (resumeProject(r.id)) auditResumeOk++;
    }
    for (const r of verifyOrphans) {
      // resume=true：复用已收集的部分 exploit_report 只续测剩余漏洞，避免清空已产出结果。
      if (r.status === 'completed') enqueueVerify(r.id, true);
      else resumeProject(r.id);
    }
    const recoveredSingles = recoverPendingVerifyOneJobs();
    if (recoveredSingles > 0) {
      console.log(`[code] 已恢复 ${recoveredSingles} 个重启前排队/运行中的单漏洞验证`);
    }
    // 一次性：恢复「仅 Web 端」策略在启动时误暂停、且尚未识别 has_web 的审计任务
    if (getSetting('mispaused_audit_recovery_v1') !== '1') {
      const { recovered } = recoverMispausedAudits();
      setSetting('mispaused_audit_recovery_v1', '1');
      if (recovered > 0) {
        console.log(`[code] 已恢复 ${recovered} 个因 Web-only 策略误暂停的审计任务`);
      }
    }
    // 校正：按「最新一轮是否真正跑完」动态归入完成/中途暂停（审计与验证同理）
    // 推迟并拆开，避免与 HTTP 抢同一事件循环（全库 agent_events + 可能的磁盘补入库）
    setTimeout(() => {
      try {
        const fixed = reconcileMispausedCompletedAudits();
        if (fixed > 0) {
          console.log(`[code] 已按完成态动态校正 ${fixed} 个项目（完成↔中途暂停）`);
        }
      } catch (e) {
        console.error('[code] 完成态动态校正失败', e);
      }
    }, 3000);
    if (total > 0) console.log(`[code] 已自动恢复 ${total} 个中断的任务（智能续跑，复用已有产物）`);
  }, 500);
}

const app = express();
app.use(cors());
app.use(compression({ threshold: 1024 }));
app.use(express.json({ limit: '10mb' }));
app.use('/api', routes);

app.get('/api/health', (_req, res) => res.json({ ok: true, ts: Date.now() }));

// 生产托管：存在 frontend/dist 时由后端同端口提供 SPA（npm run start:web）
const frontendDist = path.join(__dirname, '..', '..', 'frontend', 'dist');
const frontendIndex = path.join(frontendDist, 'index.html');
if (fs.existsSync(frontendIndex)) {
  app.use(express.static(frontendDist, { index: false, maxAge: '1h' }));
  app.use((req, res, next) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') return next();
    const p = req.path || '';
    if (p.startsWith('/api') || p.startsWith('/internal') || p.startsWith('/ws')) return next();
    res.sendFile(frontendIndex);
  });
}

const server = http.createServer(app);
initWebSocket(server);

// 端口被占用 → 说明已有另一个后端实例在跑，本实例必须【立即退出】，
// 绝不能继续存活并 spawn Pi（否则就是多后端并发跑同一项目的僵尸根因）。
server.on('error', (err: NodeJS.ErrnoException) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`[code] 端口 ${PORT} 已被占用，说明已有后端实例在运行；本实例退出以避免重复运行任务。`);
    process.exit(1);
  }
  console.error('[code] 服务器错误：', err);
  process.exit(1);
});

server.listen(PORT, BIND_HOST, () => {
  console.log(`[code] 后端服务已启动: http://${BIND_HOST}:${PORT}`);
  console.log('[code] 以 Pi 为本地引擎');
  startMonitorScheduler();
  // SKIP_STARTUP_JOBS=1：只起 HTTP，跳过扫盘/对账/孤儿恢复（用于后端事件循环被启动任务堵死时救急）
  if (process.env.SKIP_STARTUP_JOBS === '1') {
    console.log('[code] SKIP_STARTUP_JOBS=1，已跳过启动对账与任务恢复');
    return;
  }
  // 启动后重型对账（全库 exploit_report / agent_events / 工作区扫盘）会同步占满事件循环，
  // 导致 /api/* 长时间无响应。一律推迟到下一轮事件循环，并在步骤间 yield，保证 HTTP 可服务。
  const yieldEventLoop = () => new Promise<void>((r) => setImmediate(r));
  void (async () => {
    await yieldEventLoop();
    try {
      // 一次性校正：已完成后不再每启动全表扫描 pending CHM
      if (getSetting('verify_incomplete_reconcile_v1') !== '1') {
        const fixed = reconcileFalseCompletedVerify(true);
        setSetting('verify_incomplete_reconcile_v1', '1');
        if (fixed.length > 0) {
          console.log(`[code] 已校正 ${fixed.length} 个未完整完成的验证任务并已排队续跑`);
        }
      }
    } catch (e) {
      console.error('[code] 验证完成状态校正失败', e);
    }
    await yieldEventLoop();
    // 先恢复中断任务（Web 端筛选已改由“新建审计”每批前置识别完成，不再有全局 web-only 策略）
    recoverOrphans();
    await yieldEventLoop();
    // 兜底清扫：删除无对应项目的残留工作区目录（异步、不阻塞）
    void sweepOrphanWorkspaces().catch((e) =>
      console.error('[code] 孤儿工作区清扫失败', e)
    );
    // 常驻清道夫：定时重扫，确保被占用未删净的目录在占用释放后自动清除（无需重启）
    startWorkspaceJanitor();
    setTimeout(() => {
      void harvestIdleProjectSources()
        .then((r) => {
          if (r.purged > 0) {
            console.log(`[code] 已归档审计结果并清理 ${r.purged}/${r.scanned} 个空闲项目的上传源码`);
          }
        })
        .catch((e) => console.error('[code] 审计结果归档/清源码失败', e));
    }, 8000);
    // 常驻运行日志清道夫：按保留策略滚动裁剪 project_run_logs，防止其膨胀拖慢整库
    startRunLogJanitor();
    // 常驻审计卡死看门狗：Pi Agent 已退出但 status 仍 running 时自动释放槽位并续跑后处理
    startAuditStallWatchdog();
    // 日志以 SQLite 追加式完整保留；归档下载改为按需生成，不再后台裁剪数据库。
    startEventArchiveScheduler();
    if (getSetting('sqlite_dual_log_backfill_v1') !== '1') {
      setImmediate(() => {
        try {
          const result = backfillExistingLogsToSqlite();
          if (result.projects_missing_second_layer === 0) {
            setSetting('sqlite_dual_log_backfill_v1', '1');
          }
          console.log('[code] 历史日志 SQLite 双层回填完成', result);
        } catch (error) {
          console.error('[code] 历史日志 SQLite 双层回填失败', error);
        }
      });
    }
    void reconcileEnvAndContainers().then(() => {
      console.log('[code] 靶机 env 状态与闲置容器已对账完成');
    });
    if (getSetting('env_false_failure_recovery_v3') !== '1') {
      try {
        const { reset, requeued } = recoverEnvFalseFailures();
        setSetting('env_false_failure_recovery_v3', '1');
        if (reset > 0) {
          console.log(
            `[code] 已恢复 ${reset} 个误标 env=failed 的项目${requeued > 0 ? `，其中 ${requeued} 个已重新排队预搭建` : ''}`
          );
        }
      } catch (e) {
        console.error('[code] env 误标失败恢复出错', e);
      }
    }
    startEnvReconcileScheduler();
    await yieldEventLoop();
    // 磁盘全量补入库改为一次性：每启动扫 completed 工作区会长时间占满事件循环
    if (getSetting('disk_reingest_startup_v1') === '1') return;
    await new Promise((r) => setTimeout(r, 2500));
    try {
      const { projects, vulns } = await reingestAllStaleFromDiskAsync({ yieldEvery: 1 });
      setSetting('disk_reingest_startup_v1', '1');
      if (projects > 0) {
        console.log(`[code] 已从磁盘补入库 ${projects} 个项目的 ${vulns} 条漏洞（审计完成但未落库）`);
      }
    } catch (e) {
      console.error('[code] 磁盘漏洞补入库失败', e);
    }
  })();
});
