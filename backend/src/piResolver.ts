import { execSync } from 'child_process';
import os from 'os';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { getSetting } from './settings';

let cached: string | null = null;

const persistentEnvCache = new Map<string, string | undefined>();

export const PI_INSTALL_HINT =
  'npm install -g --ignore-scripts @earendil-works/pi-coding-agent';

/** 读取 Windows 用户级 → 系统级持久化环境变量；非 Windows 回退 process.env。 */
function getPersistentEnvVar(name: string): string | undefined {
  if (persistentEnvCache.has(name)) return persistentEnvCache.get(name);
  let value: string | undefined;
  if (process.platform === 'win32') {
    for (const scope of ['User', 'Machine'] as const) {
      try {
        const v = execSync(
          `[Environment]::GetEnvironmentVariable('${name}', '${scope}')`,
          { encoding: 'utf8', windowsHide: true, timeout: 5000, shell: 'powershell.exe' }
        ).trim();
        if (v) {
          value = v;
          break;
        }
      } catch {
        /* ignore */
      }
    }
  } else {
    value = process.env[name];
  }
  persistentEnvCache.set(name, value);
  return value;
}

/** 读取 ~/.claude/settings.json 的 env 段（BaseURL、模型等，不含 API Key）。 */
function readAnthropicCliSettingsEnv(): Record<string, string> {
  const settingsPath = path.join(os.homedir(), '.claude', 'settings.json');
  try {
    const raw = JSON.parse(fs.readFileSync(settingsPath, 'utf8')) as { env?: Record<string, unknown> };
    const block = raw.env;
    if (!block || typeof block !== 'object') return {};
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(block)) {
      if (typeof v === 'string' && v.trim()) out[k] = v.trim();
    }
    return out;
  } catch {
    return {};
  }
}

function piAgentDir(): string {
  return process.env.PI_CODING_AGENT_DIR || path.join(os.homedir(), '.pi', 'agent');
}

/** 读取 ~/.pi/agent/settings.json 的 env 段；已有键不覆盖。 */
function readPiAgentEnv(): Record<string, string> {
  const settingsPath = path.join(piAgentDir(), 'settings.json');
  try {
    const raw = JSON.parse(fs.readFileSync(settingsPath, 'utf8')) as { env?: Record<string, unknown> };
    const block = raw.env;
    if (!block || typeof block !== 'object') return {};
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(block)) {
      if (typeof v === 'string' && v.trim()) out[k] = v.trim();
    }
    return out;
  } catch {
    return {};
  }
}

function parseKeyList(raw: string | undefined): string[] {
  if (!raw?.trim()) return [];
  return raw
    .split(/[,;\n\r]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** 收集可用 API Key 池（多 Key 随机轮换；单 Key 时行为与原来一致）。 */
function readAuthTokenPool(): string[] {
  const fromPoolVar = parseKeyList(getPersistentEnvVar('ANTHROPIC_AUTH_TOKENS'));
  if (fromPoolVar.length) return fromPoolVar;

  const tokenFile = path.join(os.homedir(), '.claude', 'auth_tokens.txt');
  try {
    const lines = fs
      .readFileSync(tokenFile, 'utf8')
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'));
    if (lines.length) return lines;
  } catch {
    /* ignore */
  }

  const single = getPersistentEnvVar('ANTHROPIC_AUTH_TOKEN') || getPersistentEnvVar('ANTHROPIC_API_KEY');
  return single ? [single] : [];
}

function pickRandomAuthToken(keys: string[]): string | undefined {
  if (!keys.length) return undefined;
  if (keys.length === 1) return keys[0];
  return keys[Math.floor(Math.random() * keys.length)];
}

/** 当前进程是否以 uid=0 运行（Kali 默认 root / sudo）。 */
export function isProcessRoot(): boolean {
  return typeof process.getuid === 'function' && process.getuid() === 0;
}

/**
 * 构建 spawn Pi 子进程用的环境：
 * - Anthropic Key：ANTHROPIC_AUTH_TOKENS / ~/.claude/auth_tokens.txt 多 Key 随机；否则单 Key
 * - ~/.claude/settings.json env（BaseURL、模型）
 * - ~/.pi/agent/settings.json env：不覆盖用户已配的 Pi 设置
 */
export function piSpawnEnv(): NodeJS.ProcessEnv {
  const env = { ...process.env };

  for (const [k, v] of Object.entries(readAnthropicCliSettingsEnv())) {
    env[k] = v;
  }

  const piEnv = readPiAgentEnv();
  for (const [k, v] of Object.entries(piEnv)) {
    if (!env[k]) env[k] = v;
  }

  const piHasAnthropic = !!(piEnv.ANTHROPIC_API_KEY || piEnv.ANTHROPIC_AUTH_TOKEN);
  if (!piHasAnthropic) {
    const key = pickRandomAuthToken(readAuthTokenPool());
    if (key) {
      env.ANTHROPIC_AUTH_TOKEN = key;
      delete env.ANTHROPIC_API_KEY;
    }
  }

  return env;
}

function lookOnPath(): string | null {
  try {
    const cmd = process.platform === 'win32' ? 'where pi' : 'command -v pi';
    const found = execSync(cmd, { encoding: 'utf8', timeout: 4000, windowsHide: true })
      .trim()
      .split(/\r?\n/)[0];
    if (found && fs.existsSync(found)) return found;
  } catch {
    /* ignore */
  }
  return null;
}

/** 解析本地 pi 可执行文件的真实路径。库键仍读写 claude_path，以免旧设置丢失。 */
export function resolvePiExecutable(): string {
  const configured = getSetting('claude_path').trim();
  if (configured && fs.existsSync(configured)) return configured;
  if (cached) return cached;

  try {
    const globalRoot = execSync('npm root -g', { timeout: 8000 }).toString().trim();
    const isWin = process.platform === 'win32';
    const pkg = path.join(globalRoot, '@earendil-works', 'pi-coding-agent');
    const candidates = isWin
      ? [
          path.join(pkg, 'bin', 'pi.exe'),
          path.join(pkg, 'bin', 'pi.cmd'),
          path.join(pkg, 'bin', 'pi'),
        ]
      : [path.join(pkg, 'bin', 'pi')];
    for (const c of candidates) {
      if (fs.existsSync(c)) {
        cached = c;
        return c;
      }
    }
  } catch {
    /* ignore */
  }

  const fromPath = lookOnPath();
  if (fromPath) {
    cached = fromPath;
    return cached;
  }

  return 'pi';
}

export function appendSchemaToPrompt(prompt: string, schemaStr: string): string {
  const schema = String(schemaStr || '').trim();
  if (!schema) return prompt;
  return `${prompt}

# 输出约束
会话结束前必须输出符合下列 JSON Schema 的最终对象（可同时把结果写入磁盘 JSON；后端也会解析最后一条助手消息）：
\`\`\`json
${schema}
\`\`\`
`;
}

export function cleanupPromptFile(file?: string): void {
  if (!file) return;
  try {
    fs.unlinkSync(file);
  } catch {
    /* ignore */
  }
}

export function isAgentBinToken(token: string): boolean {
  return token === 'pi' || token === 'claude';
}

/**
 * 由设置页命令模板生成 spawn argv。
 * {schema}/{dir} 不再作为 CLI 参数（schema 拼进 prompt，cwd 即工作区）。
 * 超长 prompt 写成临时文件，以 Pi 的 @file 传入。
 */
export function buildAgentCliArgs(opts: {
  template: string;
  prompt: string;
  schemaStr?: string;
}): { program: string; args: string[]; promptFile?: string; fullPrompt: string } {
  const fullPrompt = appendSchemaToPrompt(opts.prompt, opts.schemaStr || '');
  const tokens = opts.template.trim().split(/\s+/).filter(Boolean);
  const args: string[] = [];
  let needsPrompt = false;
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i];
    if (t === '{prompt}') {
      needsPrompt = true;
      continue;
    }
    if (t === '{dir}' || t === '{schema}') continue;
    args.push(t);
  }

  let promptFile: string | undefined;
  if (needsPrompt) {
    const cmdEst =
      args.reduce((n, a) => n + a.length + 1, 0) + fullPrompt.length + (tokens[0]?.length || 0);
    const useFile =
      process.platform === 'win32' ? fullPrompt.length > 1500 || cmdEst > 6500 : cmdEst > 120_000;
    if (useFile) {
      promptFile = path.join(os.tmpdir(), `code-pi-prompt-${crypto.randomUUID()}.md`);
      fs.writeFileSync(promptFile, fullPrompt, 'utf8');
      args.push(`@${promptFile}`);
    } else {
      args.push(fullPrompt);
    }
  }

  const token = tokens[0] || 'pi';
  const program = isAgentBinToken(token) ? resolvePiExecutable() : token;
  return { program, args, promptFile, fullPrompt };
}
