import assert from 'node:assert/strict';
import test from 'node:test';
import { decodeJsonArtifact, parseJsonArtifact } from './textEncoding';

test('keeps valid UTF-8 JSON artifact text unchanged', () => {
  const input = Buffer.from('{"title":"中文"}', 'utf8');
  assert.equal(decodeJsonArtifact(input), '{"title":"中文"}');
});

test('recovers GB18030 Chinese JSON instead of replacement characters', () => {
  // {"title":"中文"} where 中文 is GB18030/GBK bytes D6 D0 CE C4.
  const input = Buffer.from([
    ...Buffer.from('{"title":"', 'ascii'),
    0xd6,
    0xd0,
    0xce,
    0xc4,
    ...Buffer.from('"}', 'ascii'),
  ]);
  const decoded = decodeJsonArtifact(input);
  assert.equal(decoded, '{"title":"中文"}');
  assert.deepEqual(JSON.parse(decoded), { title: '中文' });
});

test('repairs literal newlines inside an agent JSON string', () => {
  const raw = '{"name":"chain","detail":"first line\nsecond line"}';
  assert.deepEqual(parseJsonArtifact(raw), {
    name: 'chain',
    detail: 'first line\nsecond line',
  });
});

test('repairs stray backslashes in a pasted evidence string', () => {
  const raw = '{"code":"$value = \\$this->field;"}';
  assert.deepEqual(parseJsonArtifact(raw), {
    code: '$value = \\$this->field;',
  });
});
