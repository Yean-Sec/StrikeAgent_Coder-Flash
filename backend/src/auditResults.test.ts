import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import test from 'node:test';
import {
  ensureArtifactLayout,
  harvestAuditResults,
  resolveArtifactRoot,
  resultsDirFor,
} from './auditResults';

test('harvestAuditResults copies JSON and vuln reports into identified results dir', () => {
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'harvest-ws-'));
  const projectId = 'p_test_harvest';
  try {
    fs.mkdirSync(path.join(ws, 'JSON'));
    fs.writeFileSync(path.join(ws, 'JSON', 'php-security-guard.json'), '[{"title":"x"}]', 'utf8');
    fs.writeFileSync(path.join(ws, 'directly_exploitable_vulns.json'), '[]', 'utf8');
    fs.mkdirSync(path.join(ws, 'MD漏洞复现'));
    fs.writeFileSync(path.join(ws, 'MD漏洞复现', 'a.md'), '# a\n', 'utf8');
    fs.writeFileSync(path.join(ws, 'src.php'), '<?php echo 1;', 'utf8');
    const destBefore = resultsDirFor(projectId);
    if (fs.existsSync(destBefore)) fs.rmSync(destBefore, { recursive: true, force: true });

    const out = harvestAuditResults({
      projectId,
      projectName: 'demo-app',
      archiveName: 'demo.zip',
      workspacePath: ws,
    });
    assert.equal(out.dest, destBefore);
    assert.ok(out.copied.includes('JSON'));
    assert.ok(fs.existsSync(path.join(out.dest, 'JSON', 'php-security-guard.json')));
    assert.ok(fs.existsSync(path.join(out.dest, 'MD漏洞复现', 'a.md')));
    assert.ok(fs.existsSync(path.join(out.dest, 'MANIFEST.json')));
    const manifest = JSON.parse(fs.readFileSync(path.join(out.dest, 'MANIFEST.json'), 'utf8'));
    assert.equal(manifest.project_id, projectId);
    assert.equal(manifest.project_name, 'demo-app');
    assert.equal(resolveArtifactRoot(projectId, ws), out.dest);
    fs.rmSync(ws, { recursive: true, force: true });
    assert.equal(resolveArtifactRoot(projectId, ws), out.dest);
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
    const dest = resultsDirFor(projectId);
    if (fs.existsSync(dest)) fs.rmSync(dest, { recursive: true, force: true });
  }
});

test('ensureArtifactLayout stores JSON writes in data/results, not source tree', () => {
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'layout-ws-'));
  const projectId = 'p_test_layout';
  const dest = resultsDirFor(projectId);
  try {
    if (fs.existsSync(dest)) fs.rmSync(dest, { recursive: true, force: true });
    fs.writeFileSync(path.join(ws, 'app.php'), '<?php echo 1;', 'utf8');
    const art = ensureArtifactLayout(projectId, ws);
    assert.equal(art, dest);
    assert.ok(fs.existsSync(path.join(ws, 'app.php')));
    fs.writeFileSync(path.join(ws, 'JSON', 'php-security-guard.json'), '[{"title":"via-ws"}]', 'utf8');
    assert.ok(fs.existsSync(path.join(dest, 'JSON', 'php-security-guard.json')));
    assert.equal(
      fs.readFileSync(path.join(dest, 'JSON', 'php-security-guard.json'), 'utf8'),
      '[{"title":"via-ws"}]'
    );
    assert.ok(fs.lstatSync(path.join(ws, 'JSON')).isSymbolicLink());
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
    if (fs.existsSync(dest)) fs.rmSync(dest, { recursive: true, force: true });
  }
});
