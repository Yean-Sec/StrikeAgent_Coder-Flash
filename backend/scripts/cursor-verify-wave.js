/**
 * One-shot wave: assemble batch files, normalize, stub uncovered pending, partial commit.
 * Usage: node scripts/cursor-verify-wave.js <projectId> [--stub]
 */
const { execSync } = require('child_process');
const path = require('path');

const projectId = process.argv[2];
const stub = process.argv.includes('--stub');
if (!projectId) {
  console.error('Usage: node cursor-verify-wave.js <projectId> [--stub]');
  process.exit(1);
}

const root = path.join(__dirname, '..');
const run = (cmd) => {
  console.log('>', cmd);
  execSync(cmd, { cwd: root, stdio: 'inherit' });
};

run(`node scripts/cursor-verify-assemble-batches.js ${projectId}`);
run(`node scripts/cursor-verify-normalize-exploits.js ${projectId}`);
if (stub) run(`node scripts/cursor-verify-stub-pending.js ${projectId}`);
if (stub) run(`node scripts/cursor-verify-normalize-exploits.js ${projectId}`);
run(`npx tsx scripts/cursor-verify-commit.ts ${projectId} --partial`);
run(`node scripts/cursor-verify-pending.js ${projectId}`);
