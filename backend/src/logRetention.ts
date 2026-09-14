import fs from 'fs';
import path from 'path';
import db from './db';
import {
  decodeEventArchive,
  EVENT_ARCHIVE_DIR,
  type ArchivedEvent,
} from './eventArchive';

export interface HistoricalLogBackfillResult {
  archive_files: number;
  archive_events_seen: number;
  archive_events_restored: number;
  structured_events: number;
  legacy_run_logs_inserted: number;
  run_log_rows: number;
  legacy_run_log_rows: number;
  projects_with_events: number;
  projects_with_second_layer: number;
  projects_missing_second_layer: number;
}

const insertArchivedEvent = db.prepare(
  `INSERT OR IGNORE INTO agent_events
     (id, project_id, ts, kind, agent, tool, text, raw, phase)
   VALUES (@id, @project_id, @ts, @kind, @agent, @tool, @text, @raw, @phase)`
);

const insertLegacyRunLog = db.prepare(
  `INSERT OR IGNORE INTO project_run_logs
     (id, project_id, run_id, ts, phase, channel, stream, seq, content)
   VALUES (@id, @project_id, @run_id, @ts, @phase, 'legacy', 'legacy_event', @seq, @content)`
);

/**
 * 将历史 gzip 归档重新并回 agent_events，再把每条可恢复的结构化事件复制到
 * project_run_logs 第二层。原始 Pi Agent stdout/stderr 在旧版本没有采集，无法逆向重建；
 * legacy_event 保存的是当时实际留存的完整事件对象，且迁移幂等。
 */
export function backfillExistingLogsToSqlite(): HistoricalLogBackfillResult {
  const projectIds = new Set(
    (db.prepare('SELECT id FROM projects').all() as { id: string }[]).map((row) => row.id)
  );
  let archiveFiles = 0;
  let archiveEventsSeen = 0;
  let archiveEventsRestored = 0;
  let files: string[] = [];
  try {
    files = fs
      .readdirSync(EVENT_ARCHIVE_DIR)
      .filter((name) => name.toLowerCase().endsWith('.jsonl.gz'));
  } catch {
    files = [];
  }

  for (const name of files) {
    const archive = path.join(EVENT_ARCHIVE_DIR, name);
    let events: ArchivedEvent[];
    try {
      events = decodeEventArchive(fs.readFileSync(archive));
    } catch (error) {
      console.error(`[code] 历史日志归档无法读取：${archive}`, error);
      continue;
    }
    archiveFiles++;
    archiveEventsSeen += events.length;
    const tx = db.transaction((items: ArchivedEvent[]) => {
      for (const event of items) {
        if (!projectIds.has(event.project_id)) continue;
        archiveEventsRestored += insertArchivedEvent.run({
          ...event,
          raw: String(event.raw || ''),
          phase: event.phase === 'verify' ? 'verify' : 'audit',
        }).changes;
      }
    });
    tx(events);
  }

  let lastRowid = 0;
  const structuredEvents = (
    db.prepare('SELECT COUNT(*) AS c FROM agent_events').get() as { c: number }
  ).c;
  let legacyRunLogsInserted = 0;
  for (;;) {
    const rows = db
      .prepare(
        `SELECT rowid AS source_rowid, id, project_id, ts, kind, agent, tool, text, raw, phase
         FROM agent_events e
         WHERE e.rowid > ?
           AND NOT EXISTS (
             SELECT 1 FROM project_run_logs l WHERE l.id = 'legacy_log_' || e.id
           )
         ORDER BY e.rowid ASC
         LIMIT 5000`
      )
      .all(lastRowid) as (ArchivedEvent & { source_rowid: number })[];
    if (rows.length === 0) break;
    const tx = db.transaction((items: (ArchivedEvent & { source_rowid: number })[]) => {
      for (const event of items) {
        legacyRunLogsInserted += insertLegacyRunLog.run({
          id: `legacy_log_${event.id}`,
          project_id: event.project_id,
          run_id: `legacy_${event.project_id}`,
          ts: event.ts,
          phase: event.phase === 'verify' ? 'verify' : 'audit',
          seq: event.source_rowid,
          content: JSON.stringify({
            id: event.id,
            project_id: event.project_id,
            ts: event.ts,
            kind: event.kind,
            agent: event.agent,
            tool: event.tool,
            text: event.text,
            raw: event.raw,
            phase: event.phase,
          }),
        }).changes;
      }
    });
    tx(rows);
    lastRowid = rows[rows.length - 1].source_rowid;
  }

  const projectsWithEvents = (
    db.prepare('SELECT COUNT(DISTINCT project_id) AS c FROM agent_events').get() as { c: number }
  ).c;
  const runLogRows = (
    db.prepare('SELECT COUNT(*) AS c FROM project_run_logs').get() as { c: number }
  ).c;
  const legacyRunLogRows = (
    db
      .prepare("SELECT COUNT(*) AS c FROM project_run_logs WHERE stream = 'legacy_event'")
      .get() as { c: number }
  ).c;
  const projectsWithSecondLayer = (
    db.prepare('SELECT COUNT(DISTINCT project_id) AS c FROM project_run_logs').get() as {
      c: number;
    }
  ).c;
  const projectsMissingSecondLayer = (
    db
      .prepare(
        `SELECT COUNT(*) AS c
         FROM (
           SELECT DISTINCT e.project_id
           FROM agent_events e
           LEFT JOIN project_run_logs l ON l.project_id = e.project_id
           WHERE l.project_id IS NULL
         )`
      )
      .get() as { c: number }
  ).c;
  return {
    archive_files: archiveFiles,
    archive_events_seen: archiveEventsSeen,
    archive_events_restored: archiveEventsRestored,
    structured_events: structuredEvents,
    legacy_run_logs_inserted: legacyRunLogsInserted,
    run_log_rows: runLogRows,
    legacy_run_log_rows: legacyRunLogRows,
    projects_with_events: projectsWithEvents,
    projects_with_second_layer: projectsWithSecondLayer,
    projects_missing_second_layer: projectsMissingSecondLayer,
  };
}
