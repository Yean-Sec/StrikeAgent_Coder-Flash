import fs from 'fs';
import path from 'path';
import { normalizeTaintChain } from './util';
import { readJsonArtifactText } from './textEncoding';

/**
 * 读取 multi-language-comprehensive-auditor 技能在项目目录中落盘的审计产物。
 *
 * 技能的高质量结果并不在 Pi Agent 的扁平 JSON 里，而在磁盘文件中：
 *   - directly_exploitable_vulns.json：去重 + 代码级验证后的「可直接利用漏洞清单」（最高价值）
 *   - JSON/ *.json：12 个专项子智能体的原始发现（覆盖面最广，但未去重/未校准）
 *   - MD-Vulnerability/ *.md：每个真阳性漏洞的深度报告
 *
 * 因此入库时应优先采集这些磁盘产物，而不是只取终端 StructuredOutput。
 */

export interface RawVuln {
  title: string;
  severity: string;
  category: string;
  file: string;
  line: number;
  description: string;
  recommendation: string;
  snippet: string;
  taint_chain: string;
}

const SEV_MAP: Record<string, string> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  moderate: 'medium',
  low: 'low',
  info: 'info',
  informational: 'info',
};

function normSeverity(s: any): string {
  const v = String(s || '').trim().toLowerCase();
  return SEV_MAP[v] || (v.includes('crit') ? 'critical' : v.includes('high') ? 'high' : v.includes('med') ? 'medium' : 'info');
}

/** 解析 "path/to/file.php:66-98" 或 "path:66" → { file, line }。 */
function splitFileLoc(raw: any): { file: string; line: number } {
  const s = String(raw || '').trim();
  if (!s) return { file: '', line: 0 };
  const m = s.match(/^(.*?):(\d+)(?:\s*-\s*\d+)?$/);
  if (m) return { file: m[1], line: parseInt(m[2], 10) || 0 };
  return { file: s, line: 0 };
}

function readRaw(file: string): string {
  try {
    return readJsonArtifactText(file);
  } catch {
    return '';
  }
}

/** 容错 JSON 解析：严格解析失败时做常见清洗后重试（去 BOM / 尾逗号 / 智能引号）。 */
function tolerantParse(txt: string): any {
  if (!txt) return null;
  try {
    return JSON.parse(txt);
  } catch {
    /* 继续清洗重试 */
  }
  const cleaned = txt
    .replace(/^\uFEFF/, '')
    .replace(/,\s*([}\]])/g, '$1') // 尾随逗号
    .replace(/[\u201C\u201D]/g, '"') // 智能双引号
    .replace(/[\u2018\u2019]/g, "'"); // 智能单引号
  try {
    return JSON.parse(cleaned);
  } catch {
    return null;
  }
}

// 漏洞对象的已知字段（用于损坏 JSON 的字段锚点抢救）
const KNOWN_FIELDS = [
  'id',
  'category',
  'name',
  'title',
  'vulnerability',
  'severity',
  'ref_ids',
  'endpoint',
  'payload',
  'root_cause',
  'exploitation',
  'file',
  'file_path',
  'location',
  'line',
  'description',
  'remediation',
  'recommendation',
  'fix',
  'snippet',
  'impact',
];

/** 从一段（可能含未转义引号的）文本里抽取某字段的字符串值。 */
function fieldVal(seg: string, keys: string[]): string {
  const others = KNOWN_FIELDS.join('|');
  for (const key of keys) {
    // 1) 取到下一个【已知字段】之前——对值内未转义引号鲁棒
    let m = seg.match(
      new RegExp(`"${key}"\\s*:\\s*"([\\s\\S]*?)"\\s*,\\s*"(?:${others})"\\s*:`)
    );
    // 2) 取到对象结束
    if (!m) m = seg.match(new RegExp(`"${key}"\\s*:\\s*"([\\s\\S]*?)"\\s*[}\\]]`));
    // 3) 简单整段引号
    if (!m) m = seg.match(new RegExp(`"${key}"\\s*:\\s*"([^"]*)"`));
    if (m) return m[1].replace(/\\"/g, '"').replace(/\\n/g, '\n').trim();
  }
  return '';
}

/**
 * 抢救损坏 JSON（Pi Agent 常把中文/嵌套引号写成未转义）的漏洞清单：
 * 以 name/title/vulnerability 字段为对象锚点切分，逐字段正则提取，尽量不丢高价值发现。
 */
function salvageVulnArray(txt: string): any[] {
  if (!txt) return [];
  const anchorRe = /"(?:name|title|vulnerability)"\s*:/g;
  const idxs: number[] = [];
  let m: RegExpExecArray | null;
  while ((m = anchorRe.exec(txt))) idxs.push(m.index);
  if (idxs.length === 0) return [];

  const out: any[] = [];
  for (let i = 0; i < idxs.length; i++) {
    const seg = txt.slice(idxs[i], idxs[i + 1] ?? txt.length);
    const title = fieldVal(seg, ['name', 'title', 'vulnerability']);
    if (!title) continue;
    out.push({
      title,
      severity: fieldVal(seg, ['severity']),
      category: fieldVal(seg, ['category']),
      file: fieldVal(seg, ['file', 'file_path', 'location']),
      endpoint: fieldVal(seg, ['endpoint']),
      payload: fieldVal(seg, ['payload']),
      root_cause: fieldVal(seg, ['root_cause']),
      description: fieldVal(seg, ['description']),
      recommendation: fieldVal(seg, ['remediation', 'recommendation', 'fix']),
      snippet: fieldVal(seg, ['snippet']),
    });
  }
  return out;
}

/** 解析一个漏洞清单文件：容错解析；整体失败/为空时按字段锚点抢救。 */
function parseVulnFile(file: string): any[] {
  const txt = readRaw(file);
  if (!txt) return [];
  const arr = extractArray(tolerantParse(txt));
  if (arr.length > 0) return arr;
  // 严格/清洗解析仍拿不到 → 损坏 JSON，逐字段抢救（避免丢失高价值发现）
  return salvageVulnArray(txt);
}

export interface SubagentArtifactInspection {
  valid: boolean;
  repaired: boolean;
  findingCount: number;
  reason: 'ok' | 'missing' | 'empty' | 'malformed' | 'nonstandard';
}

const FINDING_ARRAY_KEYS = ['vulnerabilities', 'findings', 'vulns', 'results', 'issues', 'items'];

/**
 * 覆盖闸与入库共用的子智能体产物解析器。
 *
 * - 合法空数组明确表示“已审计、0 发现”，算覆盖完成。
 * - BOM/尾逗号/智能引号等可修复格式会原地规范化。
 * - 严格 JSON 失败但能抢救出漏洞条目时，写回统一 findings 结构。
 * - 只有 summary/任意对象字段而没有明确 findings 数组，不再冒充完成。
 */
export function inspectSubagentArtifact(
  file: string,
  options: { repair?: boolean } = {}
): SubagentArtifactInspection {
  if (!fs.existsSync(file)) {
    return { valid: false, repaired: false, findingCount: 0, reason: 'missing' };
  }
  const raw = readRaw(file);
  if (!raw) {
    return { valid: false, repaired: false, findingCount: 0, reason: 'empty' };
  }

  let strict: any = null;
  let strictOk = false;
  try {
    strict = JSON.parse(raw.replace(/^\uFEFF/, ''));
    strictOk = true;
  } catch {
    /* 继续走容错解析与抢救 */
  }
  const parsed = strictOk ? strict : tolerantParse(raw);
  const hasExplicitArray =
    Array.isArray(parsed) ||
    (!!parsed &&
      typeof parsed === 'object' &&
      FINDING_ARRAY_KEYS.some((key) => Array.isArray(parsed[key])));
  if (hasExplicitArray) {
    const findings = extractArray(parsed);
    let repaired = false;
    if (!strictOk && options.repair !== false) {
      fs.writeFileSync(file, JSON.stringify(parsed, null, 2), 'utf8');
      repaired = true;
    }
    return { valid: true, repaired, findingCount: findings.length, reason: 'ok' };
  }

  // 某些子智能体会给“0 发现”元数据，却漏掉数组。仅在明确 total=0 时补成合法空结果；
  // 不能把任意 summary/{} 当作完成，否则仍会掩盖漏跑。
  if (
    parsed &&
    typeof parsed === 'object' &&
    (parsed.total_findings === 0 || parsed.total_vulnerabilities_found === 0)
  ) {
    let repaired = false;
    if (options.repair !== false) {
      fs.writeFileSync(file, JSON.stringify({ ...parsed, findings: [] }, null, 2), 'utf8');
      repaired = true;
    }
    return { valid: true, repaired, findingCount: 0, reason: 'ok' };
  }

  const salvaged = salvageVulnArray(raw);
  if (salvaged.length > 0) {
    let repaired = false;
    if (options.repair !== false) {
      fs.writeFileSync(
        file,
        JSON.stringify(
          {
            findings: salvaged,
            meta: { recovered_from_malformed_json: true },
          },
          null,
          2
        ),
        'utf8'
      );
      repaired = true;
    }
    return { valid: true, repaired, findingCount: salvaged.length, reason: 'ok' };
  }

  return {
    valid: false,
    repaired: false,
    findingCount: 0,
    reason: parsed == null ? 'malformed' : 'nonstandard',
  };
}

const GENERIC_AGENT_TOKENS = new Set([
  'security',
  'auditor',
  'audit',
  'expert',
  'guard',
  'protection',
  'specialist',
  'findings',
  'finding',
  'results',
  'result',
  'report',
  'output',
  'json',
]);

function agentTokens(name: string): string[] {
  return name
    .toLowerCase()
    .replace(/\.json$/i, '')
    .split(/[^a-z0-9]+/)
    .filter((token) => token && !GENERIC_AGENT_TOKENS.has(token));
}

function aliasScore(candidate: string, expected: string): number {
  const left = new Set(agentTokens(candidate));
  const right = new Set(agentTokens(expected));
  if (left.size === 0 || right.size === 0) return 0;
  const expectedLanguage = agentTokens(expected)[0];
  if (expectedLanguage && !left.has(expectedLanguage)) return 0;
  let common = 0;
  for (const token of right) if (left.has(token)) common++;
  return common / Math.max(left.size, right.size);
}

function artifactAgentHints(file: string): string[] {
  const parsed = tolerantParse(readRaw(file));
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return [];
  return [
    parsed.agent,
    parsed.auditor,
    parsed.tool,
    parsed.type,
    parsed.agent_type,
    parsed.meta?.agent,
    parsed.meta?.auditor,
    parsed.audit_metadata?.agent,
  ]
    .filter((value): value is string => typeof value === 'string')
    .map((value) => value.trim())
    .filter(Boolean);
}

const RESERVED_JSON_ARTIFACTS = new Set([
  'master_coverage_ledger.json',
  'cross_language_chain_candidates.json',
  'cross-language-fusion-auditor.json',
  'master_supplement.json',
  'project_profile.json',
]);

/**
 * 把写错文件名但内容有效的子智能体结果迁移到固定 `JSON/<type>.json`。
 * 只接受语言 token 一致、唯一且高相似的候选，歧义时宁可留待精准补跑。
 */
export function reconcileSubagentArtifacts(
  codeDir: string,
  expectedAgents: string[],
  options: { repair?: boolean } = {}
): { relinked: { from: string; to: string }[]; normalized: string[] } {
  const shouldRepair = options.repair !== false;
  const jsonDir = path.join(codeDir, 'JSON');
  const relinked: { from: string; to: string }[] = [];
  const normalized: string[] = [];
  let files: string[] = [];
  try {
    fs.mkdirSync(jsonDir, { recursive: true });
    files = fs.readdirSync(jsonDir).filter((name) => name.toLowerCase().endsWith('.json'));
  } catch {
    return { relinked, normalized };
  }

  const expectedNames = new Set(expectedAgents.map((agent) => `${agent}.json`.toLowerCase()));
  for (const agent of expectedAgents) {
    const canonical = path.join(jsonDir, `${agent}.json`);
    const inspected = inspectSubagentArtifact(canonical, { repair: shouldRepair });
    if (inspected.repaired) normalized.push(`${agent}.json`);
  }

  const candidates = files.filter((name) => {
    const lower = name.toLowerCase();
    return (
      !expectedNames.has(lower) &&
      !lower.endsWith('.enum.json') &&
      !RESERVED_JSON_ARTIFACTS.has(lower)
    );
  });

  for (const agent of expectedAgents) {
    const canonical = path.join(jsonDir, `${agent}.json`);
    if (inspectSubagentArtifact(canonical, { repair: shouldRepair }).valid) continue;
    const ranked = candidates
      .map((name) => ({
        name,
        score: Math.max(
          aliasScore(name, agent),
          ...artifactAgentHints(path.join(jsonDir, name)).map((hint) => aliasScore(hint, agent))
        ),
      }))
      .filter((entry) => entry.score >= 0.6)
      .sort((a, b) => b.score - a.score);
    if (ranked.length === 0 || (ranked[1] && ranked[1].score === ranked[0].score)) continue;

    const source = path.join(jsonDir, ranked[0].name);
    const sourceResult = inspectSubagentArtifact(source, { repair: shouldRepair });
    if (!sourceResult.valid) continue;
    if (!shouldRepair) {
      relinked.push({ from: ranked[0].name, to: `${agent}.json` });
      candidates.splice(candidates.indexOf(ranked[0].name), 1);
      continue;
    }
    try {
      if (fs.existsSync(canonical)) {
        fs.renameSync(canonical, `${canonical}.invalid-${Date.now()}`);
      }
      fs.renameSync(source, canonical);
      relinked.push({ from: ranked[0].name, to: `${agent}.json` });
      candidates.splice(candidates.indexOf(ranked[0].name), 1);
    } catch {
      /* 文件正在被写入或无权限：不把它误判为已修复 */
    }
  }
  return { relinked, normalized };
}

/** 把任意子智能体条目归一化为标准漏洞结构。 */
function normalizeItem(it: any): RawVuln | null {
  if (!it || typeof it !== 'object') return null;
  const title = String(it.title || it.name || it.vulnerability || '').trim();
  if (!title) return null;

  // 定位：affected_files[0] / location / file 字段都可能出现
  let file = '';
  let line = 0;
  let snippet = String(it.snippet || it.code_snippet || it.code || it.payload || '');
  const af = Array.isArray(it.affected_files) ? it.affected_files[0] : null;
  if (af) {
    file = String(af.file || af.path || '');
    line = Number.isFinite(Number(af.line)) ? Number(af.line) : 0;
    if (!snippet && af.code) snippet = String(af.code);
  } else if (it.file || it.file_path || it.location) {
    const loc = splitFileLoc(it.file || it.file_path || it.location);
    file = loc.file;
    line = Number.isFinite(Number(it.line)) ? Number(it.line) : loc.line;
  }

  // 描述：尽量富集（成因 + 利用方式 + 端点 + payload）
  const parts: string[] = [];
  if (it.description) parts.push(String(it.description));
  if (it.root_cause) parts.push(`成因：${it.root_cause}`);
  if (it.endpoint) parts.push(`入口：${it.endpoint}`);
  if (it.exploitation) parts.push(`利用：${it.exploitation}`);
  if (it.payload) parts.push(`Payload：${it.payload}`);
  const description = parts.join('\n').trim() || title;

  // 污点链：子智能体可能用 taint_chain / taintChain / taint_flow / source_sink 等命名，
  // 也可能输出结构化数组而非字符串；normalizeTaintChain 统一转成可读逐跳文本，
  // 避免 String(array) 退化成 "[object Object],…" 写入库。
  const taint_chain = normalizeTaintChain(
    it.taint_chain || it.taintChain || it.taint_flow || it.source_sink || it.dataflow || ''
  ).trim();

  return {
    title,
    severity: normSeverity(it.severity),
    category: String(it.category || '').trim(),
    file,
    line,
    description,
    recommendation: String(it.remediation || it.recommendation || it.fix || '').trim(),
    snippet,
    taint_chain,
  };
}

function extractArray(j: any): any[] {
  if (!j) return [];
  if (Array.isArray(j)) return j;
  for (const key of ['vulnerabilities', 'findings', 'vulns', 'results', 'issues', 'items']) {
    if (Array.isArray(j[key])) return j[key];
  }
  return [];
}

/** 读取「可直接利用漏洞清单」（最高质量来源）。 */
export function readDirectlyExploitable(codeDir: string): RawVuln[] {
  return parseVulnFile(path.join(codeDir, 'directly_exploitable_vulns.json'))
    .map(normalizeItem)
    .filter((v): v is RawVuln => !!v);
}

/** 是否已有子智能体 JSON 产物（仅看目录，不解析内容，供批量续跑路径判定）。 */
export function hasSubagentArtifacts(codeDir: string): boolean {
  const dir = path.join(codeDir, 'JSON');
  try {
    return fs.readdirSync(dir).some((f) => {
      const lf = f.toLowerCase();
      if (!lf.endsWith('.json')) return false;
      if (lf.endsWith('.enum.json')) return false;
      if (lf === 'master_coverage_ledger.json') return false;
      return true;
    });
  } catch {
    return false;
  }
}

/** 读取 JSON/ 文件夹下全部子智能体原始发现（覆盖面最广）。 */
export function readSubagentFindings(codeDir: string): RawVuln[] {
  const dir = path.join(codeDir, 'JSON');
  let files: string[] = [];
  try {
    files = fs.readdirSync(dir).filter((f) => {
      const lf = f.toLowerCase();
      if (!lf.endsWith('.json')) return false;
      // 枚举清单与覆盖率账本是"自检凭据"，非漏洞条目，禁止混入原始发现
      if (lf.endsWith('.enum.json')) return false;
      if (lf === 'master_coverage_ledger.json') return false;
      // 跨语言候选利用链是"候选线索"（name/impact/steps 结构），非单漏洞条目，交给靶机组合验证阶段
      if (lf === 'cross_language_chain_candidates.json') return false;
      return true;
    });
  } catch {
    return [];
  }
  const out: RawVuln[] = [];
  for (const f of files) {
    for (const it of parseVulnFile(path.join(dir, f))) {
      const v = normalizeItem(it);
      if (v) out.push(v);
    }
  }
  return out;
}

/**
 * 判定一条记录是否为"组合利用链"（而非单个独立漏洞）。
 * 代码审计阶段的总漏洞只应包含单个漏洞，组合链属于靶机验证阶段（远程验证·组合）。
 * 保守规则：标题串联 ≥2 个箭头（A→B→C），或显式出现"利用链/组合利用/攻击链"等字样。
 * （单个漏洞标题里偶尔出现的单个 Source→Sink 箭头不会被误判。）
 */
function isCombinationChain(v: RawVuln): boolean {
  const t = String(v.title || '');
  const arrows = (t.match(/→|➜|⇒|->|=>/g) || []).length;
  if (arrows >= 2) return true;
  if (/(利用链|组合利用|攻击链|漏洞链|组合漏洞|exploit\s*chain|kill\s*chain)/i.test(t))
    return true;
  return false;
}

/** 从清单中剔除组合利用链，仅保留单个独立漏洞。 */
export function dropCombinationChains(vulns: RawVuln[]): RawVuln[] {
  return vulns.filter((v) => !isCombinationChain(v));
}

/**
 * 保守去重：仅当【标题归一 + 完整文件路径 + 行号】完全一致才合并。
 * 偏向保留漏洞完整性（允许少量重复），不做按文件名/类别的激进合并，避免误删不同漏洞。
 */
export function conservativeDedup(vulns: RawVuln[]): RawVuln[] {
  const seen = new Map<string, number>(); // key -> out 索引
  const out: RawVuln[] = [];
  for (const v of vulns) {
    const t = normTitle(v.title);
    if (!t) {
      out.push(v);
      continue;
    }
    const key = `${t}|${String(v.file || '').toLowerCase()}|${v.line || 0}`;
    const idx = seen.get(key);
    if (idx === undefined) {
      seen.set(key, out.length);
      out.push(v);
    } else if ((v.description?.length || 0) > (out[idx].description?.length || 0)) {
      out[idx] = v; // 完全相同：保留描述更详尽的
    }
  }
  return out;
}

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** 保留更优代表：严重度更高，其次描述更详尽。 */
function betterRep(a: RawVuln, b: RawVuln): boolean {
  const ra = SEV_RANK[a.severity] ?? 9;
  const rb = SEV_RANK[b.severity] ?? 9;
  if (ra !== rb) return ra < rb;
  return (a.description?.length || 0) > (b.description?.length || 0);
}

/** 标题归一：去除空白与标点符号，只留字母数字与中日韩字符。 */
function normTitle(s: string): string {
  return String(s || '')
    .toLowerCase()
    .replace(/[\s\p{P}\p{S}]+/gu, '');
}

/** 按某个 key 归并（key 为空的条目原样保留）。 */
function reduceByKey(items: RawVuln[], keyFn: (v: RawVuln) => string): RawVuln[] {
  const map = new Map<string, RawVuln>();
  const noKey: RawVuln[] = [];
  for (const v of items) {
    const k = keyFn(v);
    if (!k) {
      noKey.push(v);
      continue;
    }
    const prev = map.get(k);
    if (!prev || betterRep(v, prev)) map.set(k, v);
  }
  return [...map.values(), ...noKey];
}

/**
 * 两段式去重：
 *   1) 标题(归一) + 文件名：合并同名/近名同文件漏洞；
 *   2) 文件名 + 行号 + 类别：合并不同子智能体对【同一位置同类】的重复发现（标题措辞不同也能并掉）。
 */
export function dedupVulns(vulns: RawVuln[]): RawVuln[] {
  let arr = reduceByKey(vulns, (v) =>
    normTitle(v.title) ? `${normTitle(v.title)}|${path.basename(v.file || '').toLowerCase()}` : ''
  );
  arr = reduceByKey(arr, (v) =>
    v.file && v.line > 0
      ? `${path.basename(v.file).toLowerCase()}:${v.line}|${(v.category || '').toLowerCase()}`
      : ''
  );
  return arr;
}

/**
 * 汇总采集一次审计的最终漏洞清单。
 *
 * **权威结果 = 主控「语义去重 + 代码级验证」后的清单**：
 *   1) 终端 StructuredOutput / finalResult 的结构化清单（主控验证后的全量真阳性）
 *   2) directly_exploitable_vulns.json（已验证、可利用的高价值子集，用于补充端点/payload 细节）
 * 两者合并去重即为总漏洞数——**不再把子智能体的原始发现（未验证、含误报）计入总数**。
 *
 * 仅当主控完全没有产出验证清单（运行被截断等异常）时，才回退到 JSON/ 子智能体原始发现兜底，
 * 避免整次审计颗粒无收。
 */
export function collectAuditFindings(codeDir: string, structuredVulns: any[]): RawVuln[] {
  const exploitable = readDirectlyExploitable(codeDir);
  const structured = (structuredVulns || [])
    .map(normalizeItem)
    .filter((v): v is RawVuln => !!v);

  // 代码审计总漏洞只保留单个独立漏洞，剔除组合利用链（组合链属靶机验证阶段）
  const verified = dropCombinationChains(dedupVulns([...exploitable, ...structured]));
  if (verified.length > 0) return verified;

  // 兜底：主控未产出任何验证清单时，才采用子智能体原始发现，避免一无所获
  return dropCombinationChains(dedupVulns(readSubagentFindings(codeDir)));
}

/**
 * 仅从磁盘产物汇总（用于"重新汇总，不重跑 Pi"）：
 * 合并 directly_exploitable_vulns.json + JSON/ 子智能体发现并去重。
 */
export function collectFromDisk(codeDir: string): RawVuln[] {
  // 与正常审计口径一致：优先采用主控「代码级验证后的可利用清单」；
  // 仅当其完全缺失时，才回退到子智能体原始发现兜底。
  const exploitable = readDirectlyExploitable(codeDir);
  if (exploitable.length > 0) return dropCombinationChains(dedupVulns(exploitable));
  return dropCombinationChains(dedupVulns(readSubagentFindings(codeDir)));
}
