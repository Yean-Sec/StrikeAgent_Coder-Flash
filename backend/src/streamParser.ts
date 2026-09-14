export interface NormalizedEvent {
  kind:
    | 'system'
    | 'text'
    | 'tool_use'
    | 'agent_start'
    | 'tool_result'
    | 'result'
    | 'delta'
    | 'error';
  agent: string;
  tool: string;
  text: string;
}

const ORCHESTRATOR = '主控';

const PI_TOOL_NAMES: Record<string, string> = {
  bash: 'Bash',
  read: 'Read',
  write: 'Write',
  edit: 'Edit',
  grep: 'Grep',
  find: 'Glob',
  ls: 'Bash',
};

const PI_EVENT_TYPES = new Set([
  'session',
  'agent_start',
  'agent_end',
  'turn_start',
  'turn_end',
  'message_start',
  'message_update',
  'message_end',
  'tool_execution_start',
  'tool_execution_update',
  'tool_execution_end',
  'queue_update',
  'compaction_start',
  'compaction_end',
]);

function mapPiTool(name: string): string {
  const key = String(name || '').toLowerCase();
  return PI_TOOL_NAMES[key] || name || 'tool';
}

function summarizeInput(name: string, input: any): string {
  if (!input) return '';
  try {
    switch (name) {
      case 'Read':
        return input.file_path || input.path || '';
      case 'Glob':
        return input.pattern || input.path || '';
      case 'Grep':
        return input.pattern || '';
      case 'Bash':
        return input.command || '';
      case 'Task':
        return input.description || input.prompt || '';
      case 'Skill':
        return input.skill || input.command || '';
      case 'Write':
      case 'Edit':
        return input.file_path || input.path || '';
      default: {
        const s = JSON.stringify(input);
        return s.length > 160 ? s.slice(0, 160) + '…' : s;
      }
    }
  } catch {
    return '';
  }
}

/** 子智能体名称：优先用具体描述，避免所有子智能体都叫 general-purpose 而被合并。 */
export function subagentLabel(input: any): string {
  const t = input?.subagent_type;
  const desc = input?.description;
  if (desc) return String(desc);
  if (t && t !== 'general-purpose') return String(t);
  return '子智能体';
}

export function extractAssistantText(message: any): string {
  if (!message) return '';
  const c = message.content;
  if (typeof c === 'string') return c;
  if (!Array.isArray(c)) return typeof message.text === 'string' ? message.text : '';
  const parts: string[] = [];
  for (const part of c) {
    if (!part) continue;
    if (typeof part === 'string') parts.push(part);
    else if (part.type === 'text' && part.text) parts.push(String(part.text));
    else if (typeof part.text === 'string') parts.push(part.text);
  }
  return parts.join('');
}

function looksStructured(obj: any): boolean {
  return !!(
    obj &&
    typeof obj === 'object' &&
    (Array.isArray(obj.vulnerabilities) ||
      Array.isArray(obj.exploits) ||
      Array.isArray(obj.ratings) ||
      Array.isArray(obj.results) ||
      Array.isArray(obj.duplicate_groups) ||
      typeof obj.has_web === 'boolean' ||
      typeof obj.has_registration === 'boolean')
  );
}

export function tryExtractStructured(text: string): any | null {
  if (!text) return null;
  const tryParse = (s: string) => {
    try {
      const obj = JSON.parse(s);
      if (obj && typeof obj === 'object') return obj;
    } catch {
      /* ignore */
    }
    return null;
  };

  let parsed = tryParse(text.trim());
  if (parsed && looksStructured(parsed)) return parsed;

  const fenceMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fenceMatch) {
    parsed = tryParse(fenceMatch[1].trim());
    if (parsed && looksStructured(parsed)) return parsed;
  }

  const keys = [
    '"vulnerabilities"',
    '"exploits"',
    '"ratings"',
    '"results"',
    '"duplicate_groups"',
    '"has_web"',
  ];
  for (const key of keys) {
    const idx = text.indexOf(key);
    if (idx === -1) continue;
    const start = text.lastIndexOf('{', idx);
    if (start === -1) continue;
    for (let end = text.length; end > start; end--) {
      if (text[end - 1] !== '}') continue;
      parsed = tryParse(text.slice(start, end));
      if (parsed && looksStructured(parsed)) return parsed;
    }
  }
  return null;
}

function parsePiStreamObject(obj: any, contextAgent?: string): NormalizedEvent[] {
  const events: NormalizedEvent[] = [];
  const who = contextAgent || ORCHESTRATOR;
  const type = obj.type;

  if (type === 'session' || type === 'agent_start') {
    events.push({
      kind: 'system',
      agent: ORCHESTRATOR,
      tool: '',
      text: type === 'session' ? '审计会话已启动，主控智能体就绪' : '会话已启动',
    });
    return events;
  }

  if (type === 'message_update') {
    const ev = obj.assistantMessageEvent || obj.event || {};
    if (ev.type === 'text_delta') {
      const delta = typeof ev.delta === 'string' ? ev.delta : ev.delta?.text || ev.text || '';
      if (delta) events.push({ kind: 'delta', agent: who, tool: '', text: delta });
    }
    return events;
  }

  if (type === 'message_end' && obj.message?.role === 'assistant') {
    const text = extractAssistantText(obj.message).trim();
    if (text) events.push({ kind: 'text', agent: who, tool: '', text });
    return events;
  }

  if (type === 'tool_execution_start') {
    const name = mapPiTool(obj.toolName || obj.tool_name || '');
    events.push({
      kind: 'tool_use',
      agent: who,
      tool: name,
      text: summarizeInput(name, obj.args || obj.arguments || {}),
    });
    return events;
  }

  if (type === 'tool_execution_end') {
    let text = '';
    const r = obj.result;
    if (typeof r === 'string') text = r;
    else if (r && typeof r === 'object') {
      text = typeof r.output === 'string' ? r.output : JSON.stringify(r);
    }
    if (obj.isError) text = text || '工具执行失败';
    if (text.length > 240) text = text.slice(0, 240) + '…';
    events.push({ kind: 'tool_result', agent: who, tool: mapPiTool(obj.toolName || ''), text });
    return events;
  }

  if (type === 'agent_end') {
    events.push({
      kind: 'result',
      agent: ORCHESTRATOR,
      tool: '',
      text: '审计完成',
    });
    return events;
  }

  return events;
}

/**
 * 将一行 stream-json / Pi JSONL 对象解析为零个或多个标准化事件。
 * contextAgent：当该对象属于某个子智能体（带 parent_tool_use_id）时传入其名称。
 */
export function parseStreamObject(obj: any, contextAgent?: string): NormalizedEvent[] {
  const events: NormalizedEvent[] = [];
  if (!obj || typeof obj !== 'object') return events;

  if (PI_EVENT_TYPES.has(obj.type)) {
    return parsePiStreamObject(obj, contextAgent);
  }

  const who = contextAgent || ORCHESTRATOR;
  const type = obj.type;

  if (type === 'system') {
    if (obj.subtype === 'init') {
      events.push({
        kind: 'system',
        agent: ORCHESTRATOR,
        tool: '',
        text: '审计会话已初始化，主控智能体启动',
      });
    } else if (obj.subtype === 'task_started') {
      events.push({
        kind: 'agent_start',
        agent: subagentLabel(obj),
        tool: 'Agent',
        text: String(obj.description || ''),
      });
    } else if (obj.subtype === 'task_completed') {
      events.push({
        kind: 'tool_result',
        agent: contextAgent || subagentLabel(obj),
        tool: '',
        text: '子智能体任务完成',
      });
    }
    return events;
  }

  if (type === 'assistant' && obj.message?.content) {
    for (const part of obj.message.content) {
      if (part.type === 'text' && part.text?.trim()) {
        events.push({ kind: 'text', agent: who, tool: '', text: part.text.trim() });
      } else if (part.type === 'tool_use') {
        const name = part.name || 'tool';
        const summary = summarizeInput(name, part.input);
        if (name === 'Task' || name === 'Agent') {
          events.push({
            kind: 'agent_start',
            agent: subagentLabel(part.input),
            tool: name,
            text: summary,
          });
        } else if (name === 'Skill') {
          const sub = part.input?.skill || '审计技能';
          events.push({
            kind: 'agent_start',
            agent: String(sub),
            tool: 'Skill',
            text: summary,
          });
        } else if (name === 'StructuredOutput') {
          events.push({
            kind: 'text',
            agent: ORCHESTRATOR,
            tool: '',
            text: '已生成结构化结果',
          });
        } else {
          events.push({ kind: 'tool_use', agent: who, tool: name, text: summary });
        }
      }
    }
    return events;
  }

  if (type === 'user' && obj.message?.content) {
    for (const part of obj.message.content) {
      if (part.type === 'tool_result') {
        let text = '';
        const c = part.content;
        if (typeof c === 'string') text = c;
        else if (Array.isArray(c))
          text = c.map((x: any) => (typeof x === 'string' ? x : x.text || '')).join('\n');
        if (text.length > 240) text = text.slice(0, 240) + '…';
        events.push({ kind: 'tool_result', agent: who, tool: '', text });
      }
    }
    return events;
  }

  if (type === 'stream_event') {
    const ev = obj.event;
    if (ev?.type === 'content_block_delta' && ev.delta?.type === 'text_delta') {
      events.push({ kind: 'delta', agent: ORCHESTRATOR, tool: '', text: ev.delta.text || '' });
    }
    return events;
  }

  if (type === 'result') {
    events.push({
      kind: 'result',
      agent: ORCHESTRATOR,
      tool: '',
      text: obj.is_error ? '审计异常结束' : '审计完成',
    });
    return events;
  }

  return events;
}

/** 从最终输出文本中提取漏洞结构化数据。 */
export function extractVulnerabilities(resultText: string): {
  summary: string;
  vulnerabilities: any[];
} {
  const fallback = { summary: '', vulnerabilities: [] as any[] };
  if (!resultText) return fallback;

  const parsed = tryExtractStructured(resultText);
  if (parsed && Array.isArray(parsed.vulnerabilities)) {
    return { summary: parsed.summary || '', vulnerabilities: parsed.vulnerabilities };
  }

  return fallback;
}
