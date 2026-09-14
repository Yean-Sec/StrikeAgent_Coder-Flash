import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import test from 'node:test';
import {
  hasLocalComposeContract,
  isExternallyManagedTarget,
  readTargetEnvMode,
  shouldPreserveExternalContainers,
} from './projectShape';

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'project-shape-'));
}

function writeTargetEnv(dir: string, contract: Record<string, unknown>): void {
  fs.writeFileSync(path.join(dir, 'TARGET_ENV.json'), JSON.stringify(contract), 'utf8');
}

test('compose-backed mode=external is product-manageable (not pure external)', () => {
  const dir = tempDir();
  try {
    fs.writeFileSync(
      path.join(dir, 'docker-compose.strikeagent.yml'),
      'services:\n  app:\n    build: .\n',
      'utf8'
    );
    writeTargetEnv(dir, {
      mode: 'external',
      url: 'http://127.0.0.1:18001',
      compose_project: 'p_test',
      compose_file: 'docker-compose.strikeagent.yml',
      build_provenance: 'local-source',
    });
    assert.equal(readTargetEnvMode(dir), 'external');
    assert.equal(hasLocalComposeContract(dir), true);
    assert.equal(isExternallyManagedTarget(dir), false);
    assert.equal(shouldPreserveExternalContainers(dir), true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('mode=external without compose contract stays pure external', () => {
  const dir = tempDir();
  try {
    writeTargetEnv(dir, {
      mode: 'external',
      url: 'http://127.0.0.1:18001',
      build_provenance: 'local-source',
    });
    assert.equal(readTargetEnvMode(dir), 'external');
    assert.equal(hasLocalComposeContract(dir), false);
    assert.equal(isExternallyManagedTarget(dir), true);
    assert.equal(shouldPreserveExternalContainers(dir), true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('mode=mini is recognized from TARGET_ENV', () => {
  const dir = tempDir();
  try {
    writeTargetEnv(dir, {
      mode: 'mini',
      url: 'mini://local',
      image: 'php:8.3-cli',
      build_provenance: 'local-source',
    });
    assert.equal(readTargetEnvMode(dir), 'mini');
    assert.equal(hasLocalComposeContract(dir), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('compose_project without compose file is not a local contract', () => {
  const dir = tempDir();
  try {
    writeTargetEnv(dir, {
      mode: 'external',
      url: 'http://127.0.0.1:18001',
      compose_project: 'p_test',
      compose_file: 'docker-compose.strikeagent.yml',
    });
    assert.equal(hasLocalComposeContract(dir), false);
    assert.equal(isExternallyManagedTarget(dir), true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
