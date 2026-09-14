/**
 * Close cursor verify for a project: collect misplaced files, auto-fill missing batches, finish.
 * Usage: node scripts/cursor-verify-close-project.js <projectId>
 */
const { execSync } = require('child_process');
const path = require('path');

const projectId = process.argv[2];
if (!projectId) process.exit(1);
const root = path.join(__dirname, '..');
const run = (cmd) => {
  console.log('>', cmd);
  execSync(cmd, { cwd: root, stdio: 'inherit' });
};

run(`node scripts/cursor-verify-collect-exploits.js ${projectId}`);
run(`node scripts/cursor-verify-auto-fill.js ${projectId}`);
run(`node scripts/cursor-verify-wave.js ${projectId}`);
run(`node scripts/cursor-verify-finish-project.js ${projectId}`);
run(`node scripts/cursor-verify-pending.js ${projectId}`);
