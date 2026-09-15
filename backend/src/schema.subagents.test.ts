import assert from 'node:assert/strict';
import test from 'node:test';
import { AUDIT_LANGUAGES, SUBAGENTS_BY_LANG, buildAuditOrchestratorPrompt, buildSpecialtyAgentPrompt, subagentMission, subagentsForLanguage } from './schema';
import { AUDIT_PIPE } from './runner';

function missionsOf(lang: keyof typeof SUBAGENTS_BY_LANG): string {
  return SUBAGENTS_BY_LANG[lang].map((type) => subagentMission(type)).join('\n');
}

test('each language has at most 4 specialty sub-agents, not a fixed 5-lane web bucket', () => {
  for (const lang of AUDIT_LANGUAGES) {
    const agents = subagentsForLanguage(lang);
    assert.equal(agents.length, SUBAGENTS_BY_LANG[lang].length);
    assert.ok(agents.length > 0, `${lang} should have specialty lanes`);
    assert.ok(agents.length <= 4, `${lang} must stay at most 4 agents, got ${agents.length}`);
    assert.equal(new Set(agents).size, agents.length, `${lang} lanes must be unique`);
    assert.equal(agents.includes('command-exec'), false);
    assert.equal(agents.includes('sql-injection'), false);
    assert.equal(agents.includes('file-ops'), false);
    assert.equal(agents.includes('access-control'), false);
    assert.equal(agents.includes('other-web'), false);
    assert.equal(
      agents.includes(`${lang}-security-auditor`),
      false,
      `${lang} should not keep a catch-all ${lang}-security-auditor bucket`
    );
    for (const type of agents) {
      const mission = subagentMission(type);
      assert.notEqual(mission, '该语言对应类别的专项漏洞审计', `${type} missing CWE mission`);
      assert.match(mission, /CWE-\d+/, `${type} mission should cite CWE`);
    }
  }
  assert.equal(subagentsForLanguage('php').length, 4);
  assert.ok(subagentsForLanguage('php').includes('php-file-system-auditor'));
  assert.equal(subagentsForLanguage('java').length, 4);
  assert.equal(subagentsForLanguage('jsts').length, 4);
  assert.equal(subagentsForLanguage('c').length, 4);
  assert.equal(subagentsForLanguage('solidity').length, 4);
});

test('merged missions still cover the former CWE surfaces', () => {
  const java = missionsOf('java');
  assert.match(java, /CWE-78/);
  assert.match(java, /CWE-917/);
  assert.match(java, /CWE-89/);
  assert.match(java, /CWE-918/);
  assert.match(java, /CWE-22/);
  assert.match(java, /CWE-862/);
  assert.match(java, /CWE-502/);
  assert.match(java, /CWE-798/);

  const php = missionsOf('php');
  assert.match(php, /CWE-98/);
  assert.match(php, /CWE-78/);
  assert.match(php, /CWE-89/);
  assert.match(php, /CWE-918/);
  assert.match(php, /CWE-502/);

  const jsts = missionsOf('jsts');
  assert.match(jsts, /CWE-1321/);
  assert.match(jsts, /CWE-1336/);
  assert.match(jsts, /CWE-918/);
  assert.match(jsts, /CWE-502/);
  assert.match(jsts, /CWE-434/);

  const python = missionsOf('python');
  assert.match(python, /CWE-1336/);
  assert.match(python, /CWE-502/);
  assert.match(python, /CWE-918/);

  const csharp = missionsOf('csharp');
  assert.match(csharp, /CWE-611/);
  assert.match(csharp, /CWE-502/);

  const ruby = missionsOf('ruby');
  assert.match(ruby, /CWE-915/);
  assert.match(ruby, /CWE-502/);

  const rust = missionsOf('rust');
  assert.match(rust, /CWE-119/);
  assert.match(rust, /CWE-400/);
  assert.match(rust, /CWE-918/);

  const c = missionsOf('c');
  assert.match(c, /CWE-119/);
  assert.match(c, /CWE-78/);
  assert.match(c, /CWE-134/);
  assert.match(c, /CWE-362/);
  assert.match(c, /CWE-400/);

  const solidity = missionsOf('solidity');
  assert.match(solidity, /CWE-841/);
  assert.match(solidity, /CWE-284/);
  assert.match(solidity, /CWE-190/);
  assert.match(solidity, /CWE-400/);
});

test('AUDIT_PIPE includes regrade after codeverify', () => {
  assert.deepEqual(AUDIT_PIPE, ['subagent', 'dedup', 'codeverify', 'regrade']);
});

test('audit orchestrator prompt assigns every specialty lane and forbids self-audit', () => {
  const agents = subagentsForLanguage('jsts');
  const prompt = buildAuditOrchestratorPrompt('/tmp/code', 'jsts', agents);
  assert.match(prompt, /主控调度/);
  assert.match(prompt, /禁止自己逐文件挖洞/);
  assert.match(prompt, /不要再调用 Task\/Agent 重复派发/);
  assert.match(prompt, /禁止 sleep/);
  assert.match(prompt, /立即结束本会话/);
  assert.match(prompt, /禁止轮询/);
  assert.doesNotMatch(prompt, /每 30 秒/);
  assert.doesNotMatch(prompt, /ls\/Read 检查一次/);
  for (const type of agents) {
    assert.ok(prompt.includes(type), `missing lane ${type}`);
    assert.ok(prompt.includes(`JSON/${type}.json`), `missing output ${type}.json`);
  }
});

test('specialty prompts for every language stay inside the source tree and never sleep-wait', () => {
  for (const lang of AUDIT_LANGUAGES) {
    for (const type of subagentsForLanguage(lang)) {
      const prompt = buildSpecialtyAgentPrompt('/repo/src', type);
      assert.match(prompt, /检索边界/);
      assert.match(prompt, /禁止 `find \/`/);
      assert.match(prompt, /禁止 `sleep`/);
      assert.ok(prompt.includes('/repo/src'));
    }
  }
});
