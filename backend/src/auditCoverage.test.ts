import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import test from 'node:test';
import {
  inspectSubagentArtifact,
  reconcileSubagentArtifacts,
} from './auditArtifacts';
import {
  auditCompletedProjectCoverage,
  invalidateAuditCoverage,
  resetUnverifiableCompletedAudits,
} from './auditCoverageAudit';
import db from './db';
import {
  archiveProjectEvents,
  eventArchiveManifestPath,
  eventArchivePath,
} from './eventArchive';
import {
  auditResumeLane,
  auditCoverageFailureReason,
  auditCoverageSnapshot,
  isAuditCompletedForResume,
  isAuditCoverageFailureMessage,
} from './runner';

function tempWorkspace(withGo = true): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-coverage-'));
  if (withGo) fs.writeFileSync(path.join(dir, 'go.mod'), 'module example.test/audit\n\ngo 1.23\n');
  fs.mkdirSync(path.join(dir, 'JSON'), { recursive: true });
  return dir;
}

function writeExpected(dir: string, skip?: string): string[] {
  const initial = auditCoverageSnapshot(dir, { repair: false });
  assert.equal(initial.status, 'incomplete');
  for (const agent of initial.expected) {
    if (agent === skip) continue;
    fs.writeFileSync(path.join(dir, 'JSON', `${agent}.json`), '[]', 'utf8');
  }
  return initial.expected;
}

test('coverage is fail-closed when source language cannot be determined', () => {
  const dir = tempWorkspace(false);
  try {
    const coverage = auditCoverageSnapshot(dir, { repair: false });
    assert.equal(coverage.status, 'unknown_language');
    assert.match(auditCoverageFailureReason(coverage) || '', /无法确定源码语言面/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('go workspace expects language specialty lanes, not generic command-exec', () => {
  const dir = tempWorkspace();
  try {
    const coverage = auditCoverageSnapshot(dir, { repair: false });
    assert.ok(coverage.expected.length > 0);
    assert.ok(coverage.expected.includes('go-auth-audit-expert'));
    assert.equal(coverage.expected.includes('command-exec'), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('legal empty arrays count as completed sub-agent coverage', () => {
  const dir = tempWorkspace();
  try {
    const expected = writeExpected(dir);
    const coverage = auditCoverageSnapshot(dir, { repair: false });
    assert.equal(coverage.status, 'complete');
    assert.equal(coverage.zeroFinding.length, expected.length);
    assert.equal(auditCoverageFailureReason(coverage), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('coverage plan ignores generated pipeline TypeScript', () => {
  const dir = tempWorkspace();
  try {
    fs.writeFileSync(path.join(dir, 'main.go'), 'package main\n' + '/**/'.repeat(2_000), 'utf8');
    fs.mkdirSync(path.join(dir, '_code_verify'), { recursive: true });
    fs.writeFileSync(path.join(dir, '_code_verify', 'worker.ts'), 'export {};\n' + '// x\n'.repeat(20_000), 'utf8');

    const coverage = auditCoverageSnapshot(dir, { repair: false });
    assert.ok(coverage.expected.includes('go-auth-audit-expert'));
    assert.equal(
      coverage.expected.includes('jsts-rce-security-guard'),
      false,
      'generated verification scripts must not add a JavaScript specialty lane'
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('one missing expected JSON produces terminal coverage failure', () => {
  const dir = tempWorkspace();
  try {
    const expected = auditCoverageSnapshot(dir, { repair: false }).expected;
    const missing = expected[0];
    writeExpected(dir, missing);
    const coverage = auditCoverageSnapshot(dir, { repair: false });
    assert.equal(coverage.status, 'incomplete');
    assert.deepEqual(coverage.missing, [missing]);
    assert.match(auditCoverageFailureReason(coverage) || '', /1\/\d+ 个 JSON/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('salvageable malformed JSON is normalized and preserved', () => {
  const dir = tempWorkspace();
  const file = path.join(dir, 'JSON', 'go-auth-audit-expert.json');
  try {
    fs.writeFileSync(
      file,
      '{"findings":[{"title":"auth bypass","severity":"high","description":"reachable",}],}',
      'utf8'
    );
    const inspected = inspectSubagentArtifact(file, { repair: true });
    assert.equal(inspected.valid, true);
    assert.equal(inspected.repaired, true);
    assert.equal(inspected.findingCount, 1);
    assert.doesNotThrow(() => JSON.parse(fs.readFileSync(file, 'utf8')));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('misnamed valid output is uniquely relinked to canonical agent filename', () => {
  const dir = tempWorkspace();
  try {
    const expected = auditCoverageSnapshot(dir, { repair: false }).expected;
    const target = 'go-auth-audit-expert';
    assert.ok(expected.includes(target));
    writeExpected(dir, target);
    fs.writeFileSync(
      path.join(dir, 'JSON', 'go_auth.json'),
      JSON.stringify({ findings: [], meta: { agent: target } }),
      'utf8'
    );
    assert.equal(
      auditCoverageSnapshot(dir, { repair: false }).status,
      'complete',
      'dry-run must recognize a unique alias without mutating disk'
    );
    assert.equal(fs.existsSync(path.join(dir, 'JSON', `${target}.json`)), false);
    const result = reconcileSubagentArtifacts(dir, expected);
    assert.deepEqual(result.relinked, [
      { from: 'go_auth.json', to: 'go-auth-audit-expert.json' },
    ]);
    assert.equal(auditCoverageSnapshot(dir, { repair: false }).status, 'complete');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('generic filenames are relinked from the embedded agent signature', () => {
  const dir = tempWorkspace();
  const target = 'go-config-auditor';
  try {
    fs.writeFileSync(
      path.join(dir, 'JSON', 'output.json'),
      JSON.stringify({ findings: [], meta: { agent: target } }),
      'utf8'
    );
    const result = reconcileSubagentArtifacts(dir, [target]);
    assert.deepEqual(result.relinked, [
      { from: 'output.json', to: 'go-config-auditor.json' },
    ]);
    assert.equal(
      inspectSubagentArtifact(path.join(dir, 'JSON', `${target}.json`)).valid,
      true
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('summary-only nonstandard objects do not masquerade as coverage', () => {
  const dir = tempWorkspace();
  const file = path.join(dir, 'JSON', 'go-auth-audit-expert.json');
  try {
    fs.writeFileSync(file, JSON.stringify({ summary: 'done', agent: 'go auth' }), 'utf8');
    const inspected = inspectSubagentArtifact(file, { repair: true });
    assert.equal(inspected.valid, false);
    assert.equal(inspected.reason, 'nonstandard');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('coverage failure messages are routed back to continued audit', () => {
  assert.equal(
    isAuditCoverageFailureMessage('子智能体覆盖不完整：缺失 2/13 个 JSON'),
    true
  );
  assert.equal(
    isAuditCoverageFailureMessage('历史审计覆盖不完整，已从 completed 标记为 failed'),
    true
  );
  assert.equal(isAuditCoverageFailureMessage('靶机验证失败'), false);
  assert.equal(
    isAuditCompletedForResume(
      {
        status: 'failed',
        verify_status: 'completed',
        error_message: '历史审计覆盖不完整，已从 completed 标记为 failed',
      },
      true
    ),
    false
  );
  assert.equal(
    isAuditCompletedForResume(
      { status: 'failed', verify_status: 'failed', error_message: '靶机验证失败' },
      true
    ),
    true
  );
  assert.equal(
    auditResumeLane(
      {
        status: 'paused',
        verify_status: 'none',
        error_message: '审计覆盖证据缺失：审计数据已清除并转入已暂停',
      },
      true,
      true
    ),
    'reprocess'
  );
  // 磁盘无任何 JSON/ 产物时，「继续」走全量 doAudit
  assert.equal(
    auditResumeLane(
      {
        status: 'paused',
        verify_status: 'none',
        error_message: '审计覆盖证据缺失：审计数据已清除并转入已暂停',
      },
      true,
      false
    ),
    'audit'
  );
  assert.equal(
    auditResumeLane(
      {
        status: 'failed',
        verify_status: 'none',
        error_message: '子智能体覆盖不完整：缺失 2/13 个 JSON',
      },
      false,
      false
    ),
    'audit'
  );
});

test('dry-run and apply preserve JSON plus vulnerabilities and add a post-anchor failure', () => {
  const dir = tempWorkspace();
  const id = `p_test_coverage_${Date.now()}`;
  const name = `coverage-test-${Date.now()}`;
  const jsonFile = path.join(dir, 'JSON', 'go-auth-audit-expert.json');
  fs.writeFileSync(jsonFile, '[]', 'utf8');
  const rollback = new Error('ROLLBACK_TEST');
  try {
    db.transaction(() => {
      const ts = Date.now() - 1000;
      db.prepare(
        `INSERT INTO projects
          (id, project_name, archive_name, source_type, source_ref, workspace_path,
           status, verify_status, created_at, started_at, finished_at)
         VALUES (?, ?, '', 'github', 'https://example.test/audit.git', ?,
                 'completed', 'completed', ?, ?, ?)`
      ).run(id, name, dir, ts, ts, ts);
      db.prepare(
        `INSERT INTO vulnerabilities
          (id, project_id, title, severity, category, file_path, line, description,
           recommendation, code_snippet, taint_chain, created_at, verified)
         VALUES (?, ?, 'test finding', 'high', 'auth', 'main.go', 1, 'kept',
                 '', '', '', ?, 1)`
      ).run(`v_${id}`, id, ts);
      db.prepare(
        `INSERT INTO agent_events
          (id, project_id, ts, kind, agent, tool, text, raw, phase)
         VALUES (?, ?, ?, 'system', '主控', '', '✓ 代码级验证完成', '', 'audit')`
      ).run(`e_anchor_${id}`, id, ts);
      db.prepare(
        `INSERT INTO agent_events
          (id, project_id, ts, kind, agent, tool, text, raw, phase)
         VALUES (?, ?, ?, 'text', '主控', '', '历史远程验证日志', '{"kept":true}', 'verify')`
      ).run(`e_verify_${id}`, id, ts + 1);

      const verdict = auditCompletedProjectCoverage().projects.find(
        (project) => project.project_id === id
      );
      assert.ok(verdict);
      assert.equal(verdict.should_invalidate, true);
      assert.equal(verdict.classification, 'incomplete');
      assert.ok(verdict.missing_agents.length > 0);

      const applied = invalidateAuditCoverage(id, verdict);
      assert.equal(applied.ok, true);
      const project = db
        .prepare('SELECT status, verify_status FROM projects WHERE id = ?')
        .get(id) as { status: string; verify_status: string };
      assert.deepEqual(project, { status: 'failed', verify_status: 'none' });
      assert.equal(
        (db.prepare('SELECT COUNT(*) AS c FROM vulnerabilities WHERE project_id = ?').get(id) as {
          c: number;
        }).c,
        1
      );
      assert.equal(fs.existsSync(jsonFile), true);
      assert.equal(
        (
          db
            .prepare(
              `SELECT COUNT(*) AS c FROM agent_events
               WHERE project_id = ? AND phase = 'verify'`
            )
            .get(id) as { c: number }
        ).c,
        1
      );
      const failure = db
        .prepare(
          `SELECT ts, kind FROM agent_events
           WHERE project_id = ? AND agent = '审计完整性校验器'
           ORDER BY ts DESC LIMIT 1`
        )
        .get(id) as { ts: number; kind: string };
      assert.equal(failure.kind, 'error');
      assert.ok(failure.ts > ts);
      throw rollback;
    })();
  } catch (error) {
    if (error !== rollback) throw error;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('unverifiable reset clears findings, moves to paused, and preserves all database logs', () => {
  const id = `p_test_reset_${Date.now()}`;
  const name = `reset-test-${Date.now()}`;
  const rollback = new Error('ROLLBACK_RESET_TEST');
  try {
    db.transaction(() => {
      const ts = Date.now() - 1000;
      db.prepare(
        `INSERT INTO projects
          (id, project_name, archive_name, source_type, source_ref, workspace_path,
           status, verify_status, created_at, started_at, finished_at)
         VALUES (?, ?, '', 'github', 'https://example.test/reset.git', NULL,
                 'completed', 'completed', ?, ?, ?)`
      ).run(id, name, ts, ts, ts);
      db.prepare(
        `INSERT INTO vulnerabilities
          (id, project_id, title, severity, category, file_path, line, description,
           recommendation, code_snippet, taint_chain, created_at)
         VALUES (?, ?, 'stale finding', 'high', 'auth', 'main.go', 1, 'stale',
                 '', '', '', ?)`
      ).run(`v_${id}`, id, ts);
      db.prepare(
        `INSERT INTO agent_events
          (id, project_id, ts, kind, agent, tool, text, raw, phase)
         VALUES (?, ?, ?, 'result', '主控', '', '审计完成', '{"kept":true}', 'audit')`
      ).run(`e_${id}`, id, ts);
      db.prepare(
        `INSERT INTO project_run_logs
          (id, project_id, run_id, ts, phase, channel, stream, seq, content)
         VALUES (?, ?, ?, ?, 'audit', 'main', 'stdout', 0, 'raw log kept')`
      ).run(`log_${id}`, id, `run_${id}`, ts);

      const result = resetUnverifiableCompletedAudits([id]);
      assert.deepEqual(result.reset, [id]);
      const project = db
        .prepare(
          `SELECT status, verify_status, workspace_path, count_high
           FROM projects WHERE id = ?`
        )
        .get(id) as {
        status: string;
        verify_status: string;
        workspace_path: string | null;
        count_high: number;
      };
      assert.deepEqual(project, {
        status: 'paused',
        verify_status: 'none',
        workspace_path: null,
        count_high: 0,
      });
      assert.equal(
        (db.prepare('SELECT COUNT(*) AS c FROM vulnerabilities WHERE project_id = ?').get(id) as {
          c: number;
        }).c,
        0
      );
      assert.equal(
        (db.prepare('SELECT COUNT(*) AS c FROM agent_events WHERE project_id = ?').get(id) as {
          c: number;
        }).c,
        2
      );
      assert.equal(
        (db.prepare('SELECT COUNT(*) AS c FROM project_run_logs WHERE project_id = ?').get(id) as {
          c: number;
        }).c,
        1
      );
      throw rollback;
    })();
  } catch (error) {
    if (error !== rollback) throw error;
  }
});

test('event archive creates a backup without pruning SQLite events', () => {
  const id = `p_test_archive_${Date.now()}`;
  const name = `archive-test-${Date.now()}`;
  const rollback = new Error('ROLLBACK_ARCHIVE_TEST');
  try {
    db.transaction(() => {
      const ts = Date.now();
      db.prepare(
        `INSERT INTO projects
          (id, project_name, archive_name, source_type, source_ref, status, created_at)
         VALUES (?, ?, '', 'github', 'https://example.test/archive.git', 'paused', ?)`
      ).run(id, name, ts);
      db.prepare(
        `INSERT INTO agent_events
          (id, project_id, ts, kind, agent, tool, text, raw, phase)
         VALUES (?, ?, ?, 'text', '主控', '', 'full log', '{"raw":true}', 'audit')`
      ).run(`e_${id}`, id, ts);
      const archived = archiveProjectEvents(id, 0);
      assert.equal(archived.archived, 1);
      assert.equal(archived.deleted, 0);
      assert.equal(
        (db.prepare('SELECT COUNT(*) AS c FROM agent_events WHERE project_id = ?').get(id) as {
          c: number;
        }).c,
        1
      );
      throw rollback;
    })();
  } catch (error) {
    if (error !== rollback) throw error;
  } finally {
    fs.rmSync(eventArchivePath(id), { force: true });
    fs.rmSync(eventArchiveManifestPath(id), { force: true });
  }
});
