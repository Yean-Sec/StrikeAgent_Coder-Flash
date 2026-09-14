import db from './db';
import { createProject } from './projectsService';
import { enqueueAudit, isPiJobsEnabled } from './runner';
import { repoNameFromUrl, now } from './util';
import { broadcast } from './ws';
import { fetchLatestRelease } from './githubMeta';
import type { Monitor } from './types';

async function checkMonitor(m: Monitor): Promise<void> {
  const latest = await fetchLatestRelease(m.repo_url);
  db.prepare('UPDATE monitors SET last_checked = ? WHERE id = ?').run(now(), m.id);
  if (!latest) {
    broadcast({ type: 'monitor_checked', monitorId: m.id, ok: false });
    return;
  }

  if (m.last_release_tag === null) {
    // 首次记录基线，不触发，避免历史版本被重复审计
    db.prepare('UPDATE monitors SET last_release_tag = ? WHERE id = ?').run(latest.tag, m.id);
    broadcast({ type: 'monitor_checked', monitorId: m.id, ok: true, tag: latest.tag, baseline: true });
    return;
  }

  if (latest.tag && latest.tag !== m.last_release_tag) {
    if (!isPiJobsEnabled()) {
      console.warn(`[code] Pi 任务已停摆，监控 ${m.id} 发现新版本 ${latest.tag} 但不自动开审`);
      db.prepare(
        'UPDATE monitors SET last_release_tag = ?, last_triggered = ? WHERE id = ?'
      ).run(latest.tag, now(), m.id);
      broadcast({
        type: 'monitor_checked',
        monitorId: m.id,
        ok: true,
        tag: latest.tag,
        skipped: 'pi_jobs_disabled',
      });
      return;
    }
    const repoName = repoNameFromUrl(m.repo_url);
    const prefix = m.project_prefix || repoName;
    const project = createProject({
      projectName: `${prefix}-${latest.tag}`,
      archiveName: `${repoName}@${latest.tag}`,
      sourceType: 'github',
      sourceRef: m.repo_url,
      sourceVersion: latest.tag,
      monitorId: m.id,
    });
    db.prepare(
      'UPDATE monitors SET last_release_tag = ?, last_triggered = ? WHERE id = ?'
    ).run(latest.tag, now(), m.id);
    enqueueAudit(project.id);
    broadcast({
      type: 'monitor_triggered',
      monitorId: m.id,
      tag: latest.tag,
      projectId: project.id,
    });
  } else {
    broadcast({ type: 'monitor_checked', monitorId: m.id, ok: true, tag: latest.tag });
  }
}

let timer: NodeJS.Timeout | null = null;

export function startMonitorScheduler(): void {
  if (timer) return;
  // 每分钟评估一次，按各监控自身间隔决定是否检查
  timer = setInterval(() => {
    const monitors = db.prepare('SELECT * FROM monitors WHERE enabled = 1').all() as Monitor[];
    const t = now();
    for (const m of monitors) {
      const intervalMs = Math.max(1, m.interval_min) * 60 * 1000;
      if (!m.last_checked || t - m.last_checked >= intervalMs) {
        void checkMonitor(m);
      }
    }
  }, 60 * 1000);
}

/** 立即检查单个监控（用于手动触发与新建时即时校验）。 */
export async function checkMonitorNow(id: string): Promise<void> {
  const m = db.prepare('SELECT * FROM monitors WHERE id = ?').get(id) as Monitor | undefined;
  if (m) await checkMonitor(m);
}
