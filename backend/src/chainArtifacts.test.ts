import assert from 'node:assert/strict';
import test from 'node:test';
import { normalizeChainArtifact } from './chainArtifacts';
import { normalizeExploitStatus } from './verificationStatus';

test('chain_name-only artifact becomes named chain with normalized status', () => {
  const out = normalizeChainArtifact({
    chain_name: '路径穿越写 webshell → RCE',
    chain_steps: [{ name: 'path traversal', status: 'success' }],
    status: 'partial',
    auth_required: 'none',
  });
  assert.ok(out);
  assert.equal(out!.name, '路径穿越写 webshell → RCE');
  assert.deepEqual(out!.steps, [{ name: 'path traversal', status: 'success' }]);
  assert.equal(out!.status, 'restricted');
  assert.equal(out!.chain_name, undefined);
});

test('nested { chain: { name } } flattens', () => {
  const out = normalizeChainArtifact({
    chain: {
      name: 'stored-xss-csrf-expression-rce',
      status: 'success',
      steps: [{ description: 'xss' }, { description: 'rce' }],
      impact: 'RCE',
    },
  });
  assert.ok(out);
  assert.equal(out!.name, 'stored-xss-csrf-expression-rce');
  assert.equal(out!.status, 'success');
  assert.equal(out!.impact, 'RCE');
});

test('string chain identifier becomes a named successful chain', () => {
  const out = normalizeChainArtifact({
    chain: 'advertiser-xss-to-plugin-upload-rce',
    status: 'verified',
    summary: '存储型 XSS 触发后成功上传插件并获得 RCE',
  });
  assert.ok(out);
  assert.equal(out!.name, 'advertiser-xss-to-plugin-upload-rce');
  assert.equal(out!.status, 'success');
});

test('overall_status is used when a chain has no status field', () => {
  const out = normalizeChainArtifact({
    chain_name: 'limited-user-chain',
    overall_status: 'confirmed_with_limitations',
  });
  assert.ok(out);
  assert.equal(out!.status, 'restricted');
});

test('source_code_verified / blocked map to terminal statuses', () => {
  assert.equal(normalizeExploitStatus('source_code_verified'), 'restricted');
  assert.equal(normalizeExploitStatus('verified_source_code'), 'restricted');
  assert.equal(normalizeExploitStatus('blocked'), 'failed');
  assert.equal(normalizeExploitStatus('confirmed_with_evidence'), 'success');
});

test('missing status derives failed from verification text', () => {
  const out = normalizeChainArtifact({
    name: 'admin-only-chain',
    detail: '验证失败：当前版本无法成立该组合链',
    auth_required: 'user',
  });
  assert.ok(out);
  assert.equal(out!.status, 'failed');
});

test('RCE proof overrides a missing generic status', () => {
  const out = normalizeChainArtifact({
    name: 'unauthenticated write → PHP execution',
    auth_required: 'none',
    verdict: 'exploitable',
    rce_confirmed: true,
    rce_proof: { output: 'uid=33(www-data) gid=33(www-data)' },
  });
  assert.ok(out);
  assert.equal(out!.status, 'success');
});

test('nested exploit_chain steps produce a terminal result', () => {
  const out = normalizeChainArtifact({
    name: 'nested steps chain',
    exploit_chain: {
      steps: [
        { status: 'PASS' },
        { status: 'BLOCKED' },
        { status: 'NOT_ACHIEVED' },
      ],
    },
  });
  assert.ok(out);
  assert.equal(out!.status, 'failed');
});

test('command proof produces success even without rce_confirmed', () => {
  const out = normalizeChainArtifact({
    name: 'command proof chain',
    rce_proof: {
      command_executed: 'id',
      output: 'uid=33(www-data) gid=33(www-data)',
    },
  });
  assert.ok(out);
  assert.equal(out!.status, 'success');
});

test('result and verdict aliases produce terminal chain statuses', () => {
  assert.equal(
    normalizeChainArtifact({ name: 'failed chain', result: 'failed' })!.status,
    'failed'
  );
  assert.equal(
    normalizeChainArtifact({ name: 'limited chain', verification_result: 'PARTIAL_SUCCESS' })!
      .status,
    'restricted'
  );
  assert.equal(
    normalizeChainArtifact({
      name: 'code-only chain',
      overall_verdict: 'SOURCE_CODE_CONFIRMED - ENVIRONMENT_BLOCKED',
    })!.status,
    'restricted'
  );
});

test('a restricted step prevents a chain without a final field from becoming success', () => {
  const out = normalizeChainArtifact({
    name: 'sink reached but HTTP trigger blocked',
    steps: [
      { status: 'success' },
      { status: 'restricted' },
      { status: 'success' },
    ],
  });
  assert.ok(out);
  assert.equal(out!.status, 'restricted');
});

test('exploit-shaped objects are not treated as chains', () => {
  const out = normalizeChainArtifact({
    vulnerability_id: 'v_abc',
    vulnerability: 'SQLi in foo',
    remote_status: 'success',
    name: 'SQLi in foo',
  });
  assert.equal(out, null);
});
