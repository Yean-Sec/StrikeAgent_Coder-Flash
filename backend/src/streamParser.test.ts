import assert from 'node:assert/strict';
import test from 'node:test';
import { parseStreamObject, tryExtractStructured } from './streamParser';

test('parseStreamObject：Pi session / agent_start 映射为 system', () => {
  const session = parseStreamObject({ type: 'session', id: 'x' });
  assert.equal(session[0]?.kind, 'system');
  const start = parseStreamObject({ type: 'agent_start' });
  assert.equal(start[0]?.kind, 'system');
  assert.match(start[0]?.text || '', /会话已启动/);
});

test('parseStreamObject：Pi tool_execution_start 映射到 Bash/Read', () => {
  const bash = parseStreamObject({
    type: 'tool_execution_start',
    toolName: 'bash',
    args: { command: 'ls -la' },
  });
  assert.equal(bash[0]?.kind, 'tool_use');
  assert.equal(bash[0]?.tool, 'Bash');
  assert.equal(bash[0]?.text, 'ls -la');

  const read = parseStreamObject({
    type: 'tool_execution_start',
    toolName: 'read',
    args: { path: '/tmp/a.ts' },
  });
  assert.equal(read[0]?.tool, 'Read');
  assert.equal(read[0]?.text, '/tmp/a.ts');
});

test('parseStreamObject：text_delta 与 agent_end', () => {
  const delta = parseStreamObject({
    type: 'message_update',
    assistantMessageEvent: { type: 'text_delta', delta: 'hello' },
  });
  assert.equal(delta[0]?.kind, 'delta');
  assert.equal(delta[0]?.text, 'hello');

  const end = parseStreamObject({ type: 'agent_end', messages: [] });
  assert.equal(end[0]?.kind, 'result');
});

test('tryExtractStructured：从助手文本取出 JSON 对象', () => {
  const obj = tryExtractStructured('前言\n```json\n{"vulnerabilities":[{"title":"x"}]}\n```\n');
  assert.ok(obj);
  assert.equal(obj.vulnerabilities[0].title, 'x');
});
