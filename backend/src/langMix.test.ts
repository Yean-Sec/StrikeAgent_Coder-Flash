import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { execFileSync } from 'child_process';
import {
  detectLanguageMix,
  detectLanguageMixHeuristic,
  languageMixFromPiJson,
  linguistJsonToTokenBytes,
  langMixCachePath,
  readLangMixCache,
  resolveLinguistBin,
  shouldSkipLangScanDir,
  isBundledOrGeneratedSourceFile,
  ensureGitRepoForLinguist,
  writeLangMixCache,
} from './langMix';

describe('shouldSkipLangScanDir / isBundledOrGeneratedSourceFile (heuristic helpers)', () => {
  it('skips static asset dirs and keeps source dirs', () => {
    assert.equal(shouldSkipLangScanDir('static'), true);
    assert.equal(shouldSkipLangScanDir('public'), true);
    assert.equal(shouldSkipLangScanDir('src'), false);
  });

  it('flags hashed / worker bundles', () => {
    assert.equal(isBundledOrGeneratedSourceFile('ts.worker-BH9nVgjN.js'), true);
    assert.equal(isBundledOrGeneratedSourceFile('auth-store.ts'), false);
  });
});

describe('linguistJsonToTokenBytes', () => {
  it('maps and merges JS/TS into jsts; drops Shell/HTML', () => {
    const bytes = linguistJsonToTokenBytes({
      Java: { size: 800, percentage: '80.00' },
      TypeScript: { size: 100, percentage: '10.00' },
      JavaScript: { size: 50, percentage: '5.00' },
      Shell: { size: 50, percentage: '5.00' },
      HTML: { size: 20, percentage: '2.00' },
    });
    assert.equal(bytes.java, 800);
    assert.equal(bytes.jsts, 150);
    assert.equal(bytes.shell, undefined);
  });
});

describe('languageMixFromPiJson', () => {
  it('maps aliases and 0–100 percents to schedulable tokens', () => {
    const mix = languageMixFromPiJson(
      {
        primary: 'Java',
        secondaries: ['TypeScript'],
        ratios: { Java: 70, TypeScript: 30 },
        reason: '第一方源码在 core/src/main/java；console/static 打包 JS 不计',
      },
      0.15
    );
    assert.ok(mix);
    assert.equal(mix.primary, 'java');
    assert.deepEqual(mix.secondaries, ['jsts']);
    assert.equal(mix.source, 'pi');
    assert.ok(Math.abs((mix.ratios.java || 0) - 0.7) < 1e-9);
    assert.ok(Math.abs((mix.ratios.jsts || 0) - 0.3) < 1e-9);
  });

  it('accepts 0–1 ratios and drops packed-JS-only secondaries below threshold', () => {
    const mix = languageMixFromPiJson(
      {
        primary: 'java',
        secondaries: [],
        ratios: { java: 0.88, jsts: 0.12 },
        reason: 'resources/static 里的 min.js 不是第一方 jsts',
      },
      0.15
    );
    assert.ok(mix);
    assert.equal(mix.primary, 'java');
    assert.deepEqual(mix.secondaries, []);
  });

  it('rejects unmapped primary', () => {
    assert.equal(languageMixFromPiJson({ primary: 'HTML', ratios: { HTML: 1 } }, 0.15), null);
  });
});

describe('lang mix cache', () => {
  it('accepts pi/linguist cache, maps leftover claude source, and rejects heuristic leftovers', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'langmix-cache-'));
    try {
      writeLangMixCache(root, {
        primary: 'java',
        secondaries: [],
        ratios: { java: 1 },
        source: 'pi',
      });
      const ok = readLangMixCache(root);
      assert.equal(ok?.primary, 'java');
      assert.equal(ok?.source, 'pi');

      fs.writeFileSync(
        langMixCachePath(root),
        JSON.stringify({
          primary: 'java',
          secondaries: [],
          ratios: { java: 1 },
          source: 'claude',
        }) + '\n'
      );
      assert.equal(readLangMixCache(root)?.source, 'pi');

      writeLangMixCache(root, {
        primary: 'jsts',
        secondaries: [],
        ratios: { jsts: 1 },
        source: 'heuristic',
      });
      assert.equal(readLangMixCache(root), null);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

describe('detectLanguageMixHeuristic', () => {
  it('does not let packaged static JS flip a Java project to jsts-primary', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'langmix-h-'));
    try {
      const javaDir = path.join(root, 'core', 'src', 'main', 'java');
      fs.mkdirSync(javaDir, { recursive: true });
      fs.writeFileSync(path.join(javaDir, 'A.java'), 'x'.repeat(50_000));
      fs.writeFileSync(path.join(javaDir, 'B.java'), 'x'.repeat(50_000));
      const staticDir = path.join(root, 'console', 'src', 'main', 'resources', 'static', 'js');
      fs.mkdirSync(staticDir, { recursive: true });
      fs.writeFileSync(path.join(staticDir, 'main.js'), 'x'.repeat(4_000_000));
      const mix = detectLanguageMixHeuristic(root, {
        secondaryThreshold: 0.15,
        fallbackPrimary: 'java',
        hasSubagents: () => true,
      });
      assert.equal(mix.primary, 'java');
      assert.equal(mix.source, 'heuristic');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

describe('GitHub Linguist integration', () => {
  const bin = resolveLinguistBin();

  it('resolveLinguistBin finds installed github-linguist', () => {
    if (!bin) {
      console.log('skip: github-linguist not installed');
      return;
    }
    assert.ok(bin.includes('github-linguist') || bin === 'github-linguist');
  });

  it('detectLanguageMix uses Linguist on a tiny git repo (Java primary)', function () {
    if (!bin) {
      console.log('skip: github-linguist not installed');
      return;
    }
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'langmix-ling-'));
    try {
      const javaDir = path.join(root, 'src', 'main', 'java');
      fs.mkdirSync(javaDir, { recursive: true });
      fs.writeFileSync(path.join(javaDir, 'App.java'), 'class App {}\n'.repeat(200));
      // package a fat js under static — Linguist should treat as generated/vendored or attrs
      const staticDir = path.join(root, 'src', 'main', 'resources', 'static');
      fs.mkdirSync(staticDir, { recursive: true });
      fs.writeFileSync(path.join(staticDir, 'app.min.js'), 'x'.repeat(500_000));
      // Match Nacos-style override so JS is not counted as JS
      fs.writeFileSync(
        path.join(root, '.gitattributes'),
        '*.js linguist-generated=true\n**/static/** linguist-vendored=true\n'
      );
      ensureGitRepoForLinguist(root);
      const mix = detectLanguageMix(root, {
        secondaryThreshold: 0.15,
        linguistBin: bin,
        hasSubagents: () => true,
      });
      assert.equal(mix.source, 'linguist');
      assert.equal(mix.primary, 'java');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('does not fall back to heuristic when Linguist is missing', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'langmix-fail-'));
    try {
      const d = path.join(root, 'src');
      fs.mkdirSync(d, { recursive: true });
      fs.writeFileSync(path.join(d, 'A.java'), 'class A {}\n'.repeat(50));
      fs.writeFileSync(path.join(d, 'app.js'), 'console.log(1)\n'.repeat(50));
      const mix = detectLanguageMix(root, {
        secondaryThreshold: 0.15,
        linguistBin: path.join(root, 'no-such-github-linguist'),
        fallbackPrimary: 'java',
        hasSubagents: () => true,
      });
      assert.equal(mix.primary, null);
      assert.notEqual(mix.source, 'heuristic');
      assert.match(String(mix.error || ''), /GitHub Linguist/);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('forceHeuristic bypasses linguist', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'langmix-force-'));
    try {
      const d = path.join(root, 'src');
      fs.mkdirSync(d, { recursive: true });
      fs.writeFileSync(path.join(d, 'a.go'), 'package main\n');
      const mix = detectLanguageMix(root, {
        secondaryThreshold: 0.15,
        forceHeuristic: true,
        hasSubagents: () => true,
      });
      assert.equal(mix.source, 'heuristic');
      assert.equal(mix.primary, 'go');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

// sanity: real github clone sample if present
describe('real sample (optional)', () => {
  it('zot clone is go-primary via linguist', () => {
    const bin = resolveLinguistBin();
    const sample = '/tmp/langmix-sample';
    if (!bin || !fs.existsSync(path.join(sample, '.git'))) {
      console.log('skip: no zot sample');
      return;
    }
    const mix = detectLanguageMix(sample, {
      secondaryThreshold: 0.15,
      linguistBin: bin,
      hasSubagents: () => true,
    });
    assert.equal(mix.source, 'linguist');
    assert.equal(mix.primary, 'go');
  });
});

// silence unused import when tests skip
void execFileSync;
