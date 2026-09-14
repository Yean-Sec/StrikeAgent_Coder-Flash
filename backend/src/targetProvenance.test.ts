import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import test from 'node:test';
import {
  PROVENANCE_LABELS,
  validateTargetProvenance,
  type ProvenanceCommandRunner,
} from './targetProvenance';

const COMMIT = '1234567890abcdef1234567890abcdef12345678';

function fixture(overrides: Record<string, unknown> = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'target-provenance-'));
  fs.writeFileSync(
    path.join(dir, 'docker-compose.code.yml'),
    'services:\n  app:\n    build: .\n',
    'utf8'
  );
  fs.writeFileSync(path.join(dir, 'VERSION_PROOF.txt'), `version=1.2.3 commit=${COMMIT}`, 'utf8');
  const contract = {
    mode: 'external',
    url: 'http://127.0.0.1:18001',
    compose_project: 'p_test',
    compose_file: 'docker-compose.code.yml',
    version: '1.2.3',
    source_version: '1.2.3',
    source_commit: COMMIT,
    build_provenance: 'local-source',
    runtime_version: '1.2.3',
    runtime_version_proof: {
      type: 'file',
      target: 'VERSION_PROOF.txt',
      contains: 'version=1.2.3',
    },
    ...overrides,
  };
  fs.writeFileSync(path.join(dir, 'TARGET_ENV.json'), JSON.stringify(contract), 'utf8');
  return dir;
}

function runner(options?: {
  dirty?: boolean;
  labels?: Record<string, string>;
}): ProvenanceCommandRunner {
  const labels =
    options?.labels ??
    ({
      [PROVENANCE_LABELS.provenance]: 'local-source',
      [PROVENANCE_LABELS.sourceVersion]: '1.2.3',
      [PROVENANCE_LABELS.sourceCommit]: COMMIT,
    } as Record<string, string>);
  return {
    run(command, args) {
      const key = `${command} ${args.join(' ')}`;
      if (key === 'git rev-parse HEAD') return COMMIT;
      if (key === 'git tag --points-at HEAD') return 'v1.2.3';
      if (key === 'git status --porcelain --untracked-files=no') {
        return options?.dirty ? ' M src/app.ts' : '';
      }
      if (key.includes('docker ps -q --filter')) return 'container-id';
      if (key === 'docker inspect --format {{json .}} container-id') {
        return JSON.stringify({ Name: '/p_test-app-1', Image: 'sha256:image' });
      }
      if (key === 'docker image inspect --format {{json .Config.Labels}} sha256:image') {
        return JSON.stringify(labels);
      }
      throw new Error(`unexpected command: ${key}`);
    },
  };
}

test('accepts exact DB → clean workspace → labeled image → runtime proof', () => {
  const dir = fixture();
  try {
    const result = validateTargetProvenance(
      { id: 'p_test', source_version: 'v1.2.3', git_ref: null },
      dir,
      runner()
    );
    assert.equal(result.ok, true, result.errors.join('\n'));
    assert.equal(result.evidence.matchingImageId, 'sha256:image');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('rejects tracked source modifications', () => {
  const dir = fixture();
  try {
    const result = validateTargetProvenance(
      { id: 'p_test', source_version: '1.2.3', git_ref: null },
      dir,
      runner({ dirty: true })
    );
    assert.equal(result.ok, false);
    assert.ok(result.errors.some((error) => error.includes('已跟踪源码修改')));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('rejects DB/contract version mismatch', () => {
  const dir = fixture({ source_version: '1.2.4', runtime_version: '1.2.4', version: '1.2.4' });
  try {
    const result = validateTargetProvenance(
      { id: 'p_test', source_version: '1.2.3', git_ref: null },
      dir,
      runner()
    );
    assert.equal(result.ok, false);
    assert.ok(result.errors.some((error) => error.includes('DB 审计版本')));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('rejects missing or mismatched image labels', () => {
  const dir = fixture();
  try {
    const result = validateTargetProvenance(
      { id: 'p_test', source_version: '1.2.3', git_ref: null },
      dir,
      runner({ labels: {} })
    );
    assert.equal(result.ok, false);
    assert.ok(result.errors.some((error) => error.includes('镜像缺少')));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('rejects runtime version conflicts', () => {
  const dir = fixture({ runtime_version: '9.9.9' });
  try {
    const result = validateTargetProvenance(
      { id: 'p_test', source_version: '1.2.3', git_ref: null },
      dir,
      runner()
    );
    assert.equal(result.ok, false);
    assert.ok(result.errors.some((error) => error.includes('运行版本')));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('static gate accepts stopped compose targets when requireLiveTarget=false', () => {
  const dir = fixture();
  try {
    const stoppedRunner: ProvenanceCommandRunner = {
      run(command, args) {
        const key = `${command} ${args.join(' ')}`;
        if (key === 'git rev-parse HEAD') return COMMIT;
        if (key === 'git tag --points-at HEAD') return 'v1.2.3';
        if (key === 'git status --porcelain --untracked-files=no') return '';
        if (key.includes('docker ps -q --filter')) {
          throw new Error('live docker ps must not run for static gate');
        }
        throw new Error(`unexpected command: ${key}`);
      },
    };
    const live = validateTargetProvenance(
      { id: 'p_test', source_version: '1.2.3', git_ref: null },
      dir,
      {
        run(command, args) {
          const key = `${command} ${args.join(' ')}`;
          if (key === 'git rev-parse HEAD') return COMMIT;
          if (key === 'git tag --points-at HEAD') return 'v1.2.3';
          if (key === 'git status --porcelain --untracked-files=no') return '';
          if (key.includes('docker ps -q --filter')) return '';
          throw new Error(`unexpected command: ${key}`);
        },
      }
    );
    assert.equal(live.ok, false);
    assert.ok(live.errors.some((error) => error.includes('未找到该 Compose 项目的运行中容器')));

    const staticOnly = validateTargetProvenance(
      { id: 'p_test', source_version: '1.2.3', git_ref: null },
      dir,
      stoppedRunner,
      { requireLiveTarget: false }
    );
    assert.equal(staticOnly.ok, true, staticOnly.errors.join('\n'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('accepts legacy compose filename and OCI labels', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'target-provenance-legacy-'));
  try {
    fs.writeFileSync(
      path.join(dir, 'docker-compose.strikeagent.yml'),
      'services:\n  app:\n    build: .\n',
      'utf8'
    );
    fs.writeFileSync(path.join(dir, 'VERSION_PROOF.txt'), `version=1.2.3 commit=${COMMIT}`, 'utf8');
    fs.writeFileSync(
      path.join(dir, 'TARGET_ENV.json'),
      JSON.stringify({
        mode: 'external',
        url: 'http://127.0.0.1:18001',
        compose_project: 'p_test',
        compose_file: 'docker-compose.strikeagent.yml',
        version: '1.2.3',
        source_version: '1.2.3',
        source_commit: COMMIT,
        build_provenance: 'local-source',
        runtime_version: '1.2.3',
        runtime_version_proof: {
          type: 'file',
          target: 'VERSION_PROOF.txt',
          contains: 'version=1.2.3',
        },
      }),
      'utf8'
    );
    const result = validateTargetProvenance(
      { id: 'p_test', source_version: 'v1.2.3', git_ref: null },
      dir,
      runner({
        labels: {
          'com.strikeagent.build-provenance': 'local-source',
          'com.strikeagent.source-version': '1.2.3',
          'com.strikeagent.source-commit': COMMIT,
        },
      })
    );
    assert.equal(result.ok, true, result.errors.join('\n'));
    assert.equal(result.evidence.matchingImageId, 'sha256:image');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
