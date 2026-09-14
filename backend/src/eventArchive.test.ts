import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { decodeEventArchive, encodeEventArchive, type ArchivedEvent } from './eventArchive';

test('gzip JSONL event archive round-trips without losing fields', () => {
  const rows: ArchivedEvent[] = [
    {
      id: 'e_1',
      project_id: 'p_test',
      ts: 1,
      kind: 'system',
      agent: '主控',
      tool: '',
      text: '开始',
      raw: '',
      phase: 'audit',
    },
    {
      id: 'e_2',
      project_id: 'p_test',
      ts: 2,
      kind: 'result',
      agent: '主控',
      tool: '',
      text: '完成',
      raw: '',
      phase: 'verify',
    },
  ];
  const encoded = encodeEventArchive(rows);
  assert.deepEqual(decodeEventArchive(encoded.gzip), rows);
  assert.equal(
    encoded.sha256,
    crypto.createHash('sha256').update(encoded.jsonl).digest('hex')
  );
});
