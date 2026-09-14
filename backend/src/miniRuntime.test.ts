import assert from 'node:assert/strict';
import path from 'path';
import test from 'node:test';
import { miniVerifyDir } from './miniRuntime';

test('miniVerifyDir 指向历史落盘目录', () => {
  assert.equal(miniVerifyDir('/tmp/ws'), path.join('/tmp/ws', '_mini_verify'));
});
