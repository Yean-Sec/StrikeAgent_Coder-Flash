/**
 * 将 _cursor_verify_global 队列中的 5 个项目写入 DB verify_status，
 * 使列表「全部进行中」与大屏「审计进行中」能展示 Cursor 主控远程验证批次。
 *
 * Usage: node scripts/cursor-verify-sync-queue-display.js
 */
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const globalDir = path.join(__dirname, '..', 'workspace', '_cursor_verify_global');
const queuePath = path.join(globalDir, 'verify_queue.json');
const activePath = path.join(globalDir, 'active_project.json');

const raw = JSON.parse(fs.readFileSync(queuePath, 'utf8'));
const active = JSON.parse(fs.readFileSync(activePath, 'utf8'));
const currentId = active.current_project_id;

const db = new Database(path.join(__dirname, '..', 'data', 'code.db'));
const now = Date.now();

const tx = db.transaction(() => {
  for (const item of raw.queue || []) {
    const id = item.id;
    if (!id) continue;
    const row = db.prepare('SELECT status FROM projects WHERE id=?').get(id);
    if (!row) {
      console.warn('skip missing project', id);
      continue;
    }
    if (row.status !== 'completed') {
      console.warn('skip audit not completed', id, row.status);
      continue;
    }
    const queueStatus = String(item.status || '').toLowerCase();
    let verify_status;
    if (queueStatus === 'completed' || item.verify_status === 'completed') {
      verify_status = 'completed';
    } else if (raw.global_status === 'completed' && !currentId) {
      verify_status = 'completed';
    } else if (id === currentId) {
      verify_status = 'running';
    } else {
      verify_status = 'queued';
    }
    const extra =
      verify_status === 'running'
        ? { verify_started_at: now, verify_error: null }
        : { verify_error: null };
    db.prepare(
      `UPDATE projects SET verify_status=@verify_status,
        verify_started_at=COALESCE(@verify_started_at, verify_started_at),
        verify_error=@verify_error
       WHERE id=@id`
    ).run({
      id,
      verify_status,
      verify_started_at: extra.verify_started_at ?? null,
      verify_error: extra.verify_error,
    });
    console.log(id, item.name, '->', verify_status);
  }
});
tx();
console.log('done');
