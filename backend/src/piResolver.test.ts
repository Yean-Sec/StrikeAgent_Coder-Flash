import assert from 'node:assert/strict';
import test from 'node:test';
import { appendSchemaToPrompt, isAgentBinToken } from './piResolver';

test('appendSchemaToPrompt：把 schema 拼进 prompt 末尾', () => {
  const out = appendSchemaToPrompt('hello', '{"type":"object"}');
  assert.ok(out.startsWith('hello'));
  assert.ok(out.includes('JSON Schema'));
  assert.ok(out.includes('{"type":"object"}'));
});

test('appendSchemaToPrompt：空 schema 不改 prompt', () => {
  assert.equal(appendSchemaToPrompt('hello', ''), 'hello');
  assert.equal(appendSchemaToPrompt('hello', '   '), 'hello');
});

test('isAgentBinToken：pi 与旧 claude 模板都走 resolver', () => {
  assert.equal(isAgentBinToken('pi'), true);
  assert.equal(isAgentBinToken('claude'), true);
  assert.equal(isAgentBinToken('/usr/bin/custom'), false);
});
