import assert from 'node:assert/strict';
import test from 'node:test';
import { parseVerifyRuntime, resolveVerifyRuntime } from './verifyMode';

test('parseVerifyRuntime：mini 映射为 full，只接受 full/none', () => {
  assert.equal(parseVerifyRuntime('mini'), 'full');
  assert.equal(parseVerifyRuntime('FULL'), 'full');
  assert.equal(parseVerifyRuntime('none'), 'none');
  assert.equal(parseVerifyRuntime(''), null);
  assert.equal(parseVerifyRuntime('compose'), null);
});

test('已写入列优先于旧 auto_verify 推断；历史 mini 视为完整靶机', () => {
  assert.equal(
    resolveVerifyRuntime({ opt_verify_runtime: 'mini', opt_auto_verify: 1 }),
    'full'
  );
  assert.equal(
    resolveVerifyRuntime({ opt_verify_runtime: 'full', opt_auto_verify: 0 }),
    'full'
  );
  assert.equal(
    resolveVerifyRuntime({ opt_verify_runtime: 'none', opt_auto_verify: 1 }),
    'none'
  );
});

test('空列 + auto_verify=1 视为完整靶机（旧项目）', () => {
  assert.equal(
    resolveVerifyRuntime({ opt_verify_runtime: null, opt_auto_verify: 1 }),
    'full'
  );
});

test('空列 + auto_verify=0 视为仅代码审计', () => {
  assert.equal(
    resolveVerifyRuntime({ opt_verify_runtime: null, opt_auto_verify: 0 }),
    'none'
  );
});

test('空列且 auto 亦空时回退全局默认；历史全局 mini 视为 full', () => {
  assert.equal(
    resolveVerifyRuntime({
      opt_verify_runtime: null,
      opt_auto_verify: null,
      globalRuntime: 'mini',
      globalAutoVerify: '1',
    }),
    'full'
  );
  assert.equal(
    resolveVerifyRuntime({
      opt_verify_runtime: null,
      opt_auto_verify: null,
      globalRuntime: '',
      globalAutoVerify: '1',
    }),
    'full'
  );
  assert.equal(
    resolveVerifyRuntime({
      opt_verify_runtime: null,
      opt_auto_verify: null,
      globalRuntime: '',
      globalAutoVerify: '0',
    }),
    'none'
  );
});
