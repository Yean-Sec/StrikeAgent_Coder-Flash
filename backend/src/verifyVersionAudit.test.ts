import assert from 'node:assert/strict';
import test from 'node:test';
import { normalizeVersionToken, versionsMatch } from './verifyVersionAudit';

test('normalizeVersionToken strips leading v and lowercases', () => {
  assert.equal(normalizeVersionToken('v4.8.2'), '4.8.2');
  assert.equal(normalizeVersionToken('V3.10.1'), '3.10.1');
  assert.equal(normalizeVersionToken(' 2.18.1-rc1 '), '2.18.1-rc1');
});

test('versionsMatch supports exact and SHA prefix equality', () => {
  assert.equal(versionsMatch('v4.8.2', '4.8.2'), true);
  assert.equal(versionsMatch('d59a618', 'd59a618abc'), true);
  assert.equal(versionsMatch('3.10.1', '3.5.0'), false);
  assert.equal(versionsMatch('2.18.1-rc1', '2.18.1'), false);
  assert.equal(versionsMatch(null, '1.0'), false);
});
