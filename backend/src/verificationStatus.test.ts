import assert from 'node:assert/strict';
import test from 'node:test';
import {
  deriveMinimumAuth,
  deriveRemoteStatus,
  normalizeExploitStatus,
  normalizePrivilegeResults,
} from './verificationStatus';

test('all restricted privilege tiers are remote restricted, not success', () => {
  const entry = {
    local_exploitable: 'success',
    local_result: '源码确认存在，但当前应用无路由入口',
    privilege_results: {
      none: { status: 'restricted', evidence: '无入口点' },
      user: { status: 'restricted', evidence: '无用户系统' },
      admin: { status: 'restricted', evidence: '无管理员系统' },
    },
  };
  assert.equal(deriveRemoteStatus(entry), 'restricted');
  assert.equal(deriveMinimumAuth(normalizePrivilegeResults(entry.privilege_results), 'none'), 'unknown');
});

test('one successful privilege tier is remote success and defines minimum auth', () => {
  const privilegeResults = normalizePrivilegeResults({
    none: { status: 'failed' },
    user: { status: 'success' },
    admin: { status: 'success' },
  });
  assert.equal(deriveRemoteStatus({ privilege_results: privilegeResults }), 'success');
  assert.equal(deriveMinimumAuth(privilegeResults, 'admin'), 'user');
});

test('legacy code-only statuses are conservatively restricted', () => {
  assert.equal(deriveRemoteStatus({ local_exploitable: 'Verified_By_Code_Analysis' }), 'restricted');
  assert.equal(
    deriveRemoteStatus({
      local_exploitable: 'Verified',
      local_result: '代码层确认漏洞存在，无远程 HTTP 入口',
    }),
    'restricted'
  );
});

test('legacy concrete remote evidence remains successful', () => {
  assert.equal(
    deriveRemoteStatus({
      local_exploitable: 'Verified',
      local_result: '向 HTTP 接口发送 payload 后成功触发并获得命令回显',
    }),
    'success'
  );
});

test('common non-standard artifact statuses are normalized', () => {
  assert.equal(normalizeExploitStatus('Partially Confirmed'), 'restricted');
  assert.equal(normalizeExploitStatus('partially_working'), 'restricted');
  assert.equal(normalizeExploitStatus('code_confirmed_env_blocked'), 'restricted');
  assert.equal(normalizeExploitStatus('blocking_issue'), 'restricted');
  assert.equal(normalizeExploitStatus('FalsePositive'), 'failed');
  assert.equal(normalizeExploitStatus('NOT_ACHIEVED'), 'failed');
  assert.equal(normalizeExploitStatus('PASS'), 'success');
  assert.equal(normalizeExploitStatus('CodeConfirmed_RemoteEndpointNotExposed'), 'restricted');
});
