import assert from 'node:assert/strict';
import test from 'node:test';
import { withinBudget } from './timeBudget';

test('withinBudget returns completed work before deadline', async () => {
  const result = await withinBudget(Promise.resolve('ok'), 100);
  assert.deepEqual(result, { timedOut: false, value: 'ok' });
});

test('withinBudget returns timeout without waiting for slow work', async () => {
  const started = Date.now();
  const result = await withinBudget(
    new Promise<string>((resolve) => setTimeout(() => resolve('late'), 80)),
    10
  );
  assert.deepEqual(result, { timedOut: true });
  assert.ok(Date.now() - started < 70);
});
