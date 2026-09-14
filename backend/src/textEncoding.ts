import fs from 'fs';

/**
 * Pi Agent 产物 are expected to be UTF-8. Some Windows proxy/CLI paths
 * nevertheless write Chinese JSON as GB18030 bytes; reading those bytes as
 * UTF-8 creates U+FFFD replacement characters and permanently pollutes DB
 * text once the JSON is parsed. Prefer UTF-8, but recover GB18030 when UTF-8
 * is demonstrably invalid.
 */
export function decodeJsonArtifact(buffer: Buffer): string {
  const utf8 = buffer.toString('utf8');
  if (!utf8.includes('\uFFFD')) return utf8;

  try {
    const gb18030 = new TextDecoder('gb18030', { fatal: true }).decode(buffer);
    // A successful GB18030 decode with no replacement characters is safer
    // than the known-corrupt UTF-8 interpretation. JSON.parse remains the
    // final validation at the caller.
    if (gb18030 && !gb18030.includes('\uFFFD')) return gb18030;
  } catch {
    /* retain UTF-8 fallback */
  }
  return utf8;
}

export function readJsonArtifactText(file: string): string {
  return decodeJsonArtifact(fs.readFileSync(file)).trim();
}

/**
 * Parse an agent artifact while tolerating literal control characters inside
 * JSON strings. This is a common partial-write mistake from CLI agents: the
 * document is otherwise valid, but a pasted newline or tab in an evidence
 * string violates JSON. Whitespace outside strings is intentionally untouched.
 */
export function parseJsonArtifact(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch (initialError) {
    let repaired = '';
    let inString = false;
    let escaped = false;

    for (const char of text) {
      if (inString && char < ' ') {
        const code = char.charCodeAt(0);
        repaired +=
          code === 0x08
            ? '\\b'
            : code === 0x09
              ? '\\t'
              : code === 0x0a
                ? '\\n'
                : code === 0x0c
                  ? '\\f'
                  : code === 0x0d
                    ? '\\r'
                    : `\\u${code.toString(16).padStart(4, '0')}`;
        continue;
      }

      if (inString && escaped) {
        // Preserve a stray backslash as a literal character instead of rejecting
        // an otherwise complete evidence string (for example `\$variable` from
        // an agent's pasted PHP snippet).
        if (!'"\\/bfnrtu'.includes(char)) repaired += '\\';
        repaired += char;
        escaped = false;
        continue;
      }

      repaired += char;
      if (inString && char === '\\') {
        escaped = true;
      } else if (char === '"') {
        inString = !inString;
      }
    }

    if (repaired === text) throw initialError;
    return JSON.parse(repaired);
  }
}
