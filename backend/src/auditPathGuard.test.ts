import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import {
  forbiddenAuditShellReason,
  createAuditPathGuardDir,
  auditGuardSpawnEnv,
} from './auditPathGuard';

const ROOT = '/home/kali/desk/proj';

test('forbids sleep-wait used by orchestrator polling', () => {
  assert.match(
    forbiddenAuditShellReason('sleep 30; ls JSON', ROOT) || '',
    /sleep 30/
  );
  assert.match(
    forbiddenAuditShellReason('sleep 60; cd /home/kali/desk/proj && ls JSON', ROOT) || '',
    /sleep 60/
  );
  assert.equal(forbiddenAuditShellReason('sleep 2', ROOT), null);
});

test('forbids find/grep starting at / for every language workspace', () => {
  assert.match(forbiddenAuditShellReason('find / -name LocalFilesystemAdapter.php', ROOT) || '', /源码目录外/);
  assert.match(forbiddenAuditShellReason('find /usr -name foo', ROOT) || '', /源码目录外/);
  assert.match(forbiddenAuditShellReason('grep -n foo /etc/passwd', ROOT) || '', /源码目录外/);
  assert.equal(forbiddenAuditShellReason('find . -name "*.php"', ROOT), null);
  assert.equal(forbiddenAuditShellReason(`grep -n foo ${ROOT}/src/a.php`, ROOT), null);
  assert.equal(forbiddenAuditShellReason('grep -n foo src/Core/Handler.php', ROOT), null);
});

test('PATH guard wrappers reject find / and long sleep, allow in-tree find', () => {
  const env = auditGuardSpawnEnv(ROOT);
  const bin = createAuditPathGuardDir(ROOT);
  const findBin = path.join(bin, 'find');
  const sleepBin = path.join(bin, 'sleep');

  const badFind = spawnSync(findBin, ['/', '-name', 'x'], {
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
  assert.notEqual(badFind.status, 0);
  assert.match(badFind.stderr, /源码目录外/);

  const badSleep = spawnSync(sleepBin, ['30'], {
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
  assert.notEqual(badSleep.status, 0);
  assert.match(badSleep.stderr, /禁止 sleep/);

  const okFind = spawnSync(findBin, [ROOT, '-maxdepth', '0'], {
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
  // ROOT may not exist in this test env; refusal only for out-of-tree. If missing, find exits 1 with no our banner.
  assert.equal((okFind.stderr || '').includes('源码目录外'), false);
});
