import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { normalizeChainArtifact } from './chainArtifacts';

/** Integration-style: disk chain shapes → normalize → named terminal chains. */
test('disk nested chain_name and chain_steps reingest shapes', () => {
  const fixtures = [
    {
      file: 'a.json',
      raw: {
        chain_name: '路径穿越写 webshell → RCE',
        chain_steps: [{ name: 'write', status: 'success' }],
        status: 'partial',
      },
    },
    {
      file: 'b.json',
      raw: {
        chain: { name: 'stored-xss-csrf-expression-rce', auth_required: 'none' },
        steps: [{ name: 'xss' }, { name: 'rce' }],
        summary: '链路完整验证通过，成功达成 RCE',
      },
    },
    {
      file: 'c.json',
      raw: {
        name: 'admin-chain',
        detail: '验证失败：当前版本无法成立该组合链',
      },
    },
  ];

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-reingest-'));
  try {
    const chainDir = path.join(dir, '_remote_verify', 'chains');
    fs.mkdirSync(chainDir, { recursive: true });
    for (const f of fixtures) {
      fs.writeFileSync(path.join(chainDir, f.file), JSON.stringify(f.raw), 'utf8');
    }

    const normalized = fs
      .readdirSync(chainDir)
      .filter((n) => n.endsWith('.json'))
      .map((n) => {
        const raw = JSON.parse(fs.readFileSync(path.join(chainDir, n), 'utf8'));
        return normalizeChainArtifact(raw);
      })
      .filter(Boolean) as Record<string, unknown>[];

    assert.equal(normalized.length, 3);
    assert.ok(normalized.every((c) => typeof c.name === 'string' && c.name.length > 0));
    assert.equal(
      normalized.find((c) => String(c.name).includes('webshell'))?.status,
      'restricted'
    );
    assert.equal(
      normalized.find((c) => c.name === 'stored-xss-csrf-expression-rce')?.status,
      'success'
    );
    assert.equal(normalized.find((c) => c.name === 'admin-chain')?.status, 'failed');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
