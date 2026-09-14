import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import zlib from 'zlib';
import db from './db';

const DATA_DIR = path.join(__dirname, '..', 'data');
export const EVENT_ARCHIVE_DIR = path.join(DATA_DIR, 'event-archives');
const DEFAULT_KEEP_RECENT = 800;

export type ArchivedEvent = {
  id: string;
  project_id: string;
  ts: number;
  kind: string;
  agent: string;
  tool: string;
  text: string;
  raw: string;
  phase: string;
};

export type EventArchiveResult = {
  projectId: string;
  archived: number;
  deleted: number;
  archivePath: string;
  sha256: string;
};

export function encodeEventArchive(events: ArchivedEvent[]): {
  jsonl: string;
  gzip: Buffer;
  sha256: string;
} {
  const jsonl = events.map((event) => JSON.stringify(event)).join('\n') + (events.length ? '\n' : '');
  const sha256 = crypto.createHash('sha256').update(jsonl).digest('hex');
  return {
    jsonl,
    gzip: zlib.gzipSync(Buffer.from(jsonl), { level: zlib.constants.Z_BEST_SPEED }),
    sha256,
  };
}

export function decodeEventArchive(buffer: Buffer): ArchivedEvent[] {
  const text = zlib.gunzipSync(buffer).toString('utf8');
  const events: ArchivedEvent[] = [];
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    events.push(JSON.parse(line) as ArchivedEvent);
  }
  return events;
}

function safeProjectId(projectId: string): string {
  const safe = String(projectId || '').replace(/[^a-zA-Z0-9_-]/g, '');
  if (!safe) throw new Error('无效项目 ID');
  return safe;
}

export function eventArchivePath(projectId: string): string {
  return path.join(EVENT_ARCHIVE_DIR, `${safeProjectId(projectId)}.jsonl.gz`);
}

export function eventArchiveManifestPath(projectId: string): string {
  return path.join(EVENT_ARCHIVE_DIR, `${safeProjectId(projectId)}.manifest.json`);
}

function readExistingArchive(projectId: string): ArchivedEvent[] {
  const archive = eventArchivePath(projectId);
  if (!fs.existsSync(archive)) return [];
  try {
    return decodeEventArchive(fs.readFileSync(archive)).filter(
      (event) => event?.id && event.project_id === projectId
    );
  } catch {
    return [];
  }
}

/**
 * 生成经校验的 gzip 备份。数据库中的事件是追加式审计证据，归档后也绝不删除。
 */
export function archiveProjectEvents(
  projectId: string,
  _keepRecent = DEFAULT_KEEP_RECENT
): EventArchiveResult {
  fs.mkdirSync(EVENT_ARCHIVE_DIR, { recursive: true });
  const current = db
    .prepare(
      `SELECT id, project_id, ts, kind, agent, tool, text, raw, phase
       FROM agent_events WHERE project_id = ? ORDER BY ts ASC, id ASC`
    )
    .all(projectId) as ArchivedEvent[];
  const byId = new Map<string, ArchivedEvent>();
  for (const event of readExistingArchive(projectId)) byId.set(event.id, event);
  for (const event of current) byId.set(event.id, event);
  const merged = [...byId.values()].sort((a, b) => a.ts - b.ts || a.id.localeCompare(b.id));
  const { jsonl, gzip, sha256 } = encodeEventArchive(merged);
  const archive = eventArchivePath(projectId);
  const temp = `${archive}.${process.pid}.tmp`;
  fs.writeFileSync(temp, gzip);

  const validated = zlib.gunzipSync(fs.readFileSync(temp)).toString('utf8');
  const validatedHash = crypto.createHash('sha256').update(validated).digest('hex');
  if (validatedHash !== sha256) {
    fs.rmSync(temp, { force: true });
    throw new Error(`日志归档校验失败：${projectId}`);
  }
  fs.renameSync(temp, archive);
  fs.writeFileSync(
    eventArchiveManifestPath(projectId),
    JSON.stringify(
      {
        projectId,
        format: 'jsonl+gzip',
        count: merged.length,
        sha256,
        firstTs: merged[0]?.ts ?? null,
        lastTs: merged.at(-1)?.ts ?? null,
        archivedAt: Date.now(),
      },
      null,
      2
    ),
    'utf8'
  );

  return {
    projectId,
    archived: merged.length,
    deleted: 0,
    archivePath: archive,
    sha256,
  };
}

export async function archiveInactiveProjects(
  options: { maxProjects?: number; minEvents?: number; keepRecent?: number } = {}
): Promise<EventArchiveResult[]> {
  const maxProjects = Math.max(1, options.maxProjects ?? 1);
  const minEvents = Math.max(DEFAULT_KEEP_RECENT, options.minEvents ?? DEFAULT_KEEP_RECENT);
  const keepRecent = Math.max(100, options.keepRecent ?? DEFAULT_KEEP_RECENT);
  const rows = db
    .prepare(
      `SELECT p.id, COUNT(e.id) AS event_count
       FROM projects p JOIN agent_events e ON e.project_id = p.id
       WHERE p.status NOT IN ('running','queued') AND p.verify_status NOT IN ('running','queued')
       GROUP BY p.id
       HAVING COUNT(e.id) > ?
       ORDER BY event_count DESC
       LIMIT ?`
    )
    .all(minEvents, maxProjects) as { id: string; event_count: number }[];
  const results: EventArchiveResult[] = [];
  for (const row of rows) {
    results.push(archiveProjectEvents(row.id, keepRecent));
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  return results;
}

let archiveTimer: NodeJS.Timeout | null = null;

export function startEventArchiveScheduler(): void {
  // SQLite 现在是完整日志的权威存储，不再后台压缩并裁剪数据库记录。
  // 下载归档时按需生成 gzip，避免定时重复归档同一追加式数据集。
  if (archiveTimer) return;
}
