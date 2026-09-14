import crypto from 'crypto';

export function newId(prefix = ''): string {
  return prefix + crypto.randomUUID().replace(/-/g, '').slice(0, 16);
}

export function now(): number {
  return Date.now();
}

/**
 * 从压缩包/文件名中尽力解析版本号。
 * 例：grav-1.8.0-beta.29-1(1).zip -> 1.8.0-beta.29；wordpress-6.4.2.zip -> 6.4.2。
 * 解析不到时返回 null（不会把上传副本编号如 -1、(1) 当成版本）。
 */
export function versionFromName(name: string): string | null {
  if (!name) return null;
  const base = name.replace(/\.(zip|rar|tar|gz|tgz|tar\.gz|7z)$/i, '');
  const m = base.match(
    /v?(\d+\.\d+(?:\.\d+)*(?:[-.](?:alpha|beta|rc|pre|preview|dev|snapshot)[0-9a-z.]*)?)/i
  );
  return m ? m[1] : null;
}

/**
 * 从压缩包/文件名中尽力解析"系统名"（去掉版本号与上传副本编号后的主体名）。
 * 例：grav-1.8.0-beta.29-1(1).zip -> grav；wordpress-6.4.2.zip -> wordpress。
 * 解析不到时返回 null。
 */
export function systemNameFromName(name: string): string | null {
  if (!name) return null;
  let base = name.replace(/\.(zip|rar|tar|gz|tgz|tar\.gz|7z)$/i, '');
  const v = versionFromName(base);
  if (v) {
    const idx = base.indexOf(v);
    if (idx > 0) base = base.slice(0, idx);
  }
  base = base
    .replace(/[-_.\s(]+$/g, '') // 去尾部分隔符/左括号
    .replace(/[-_]v$/i, '') // 去结尾的 -v / _v
    .replace(/[-_\s]\d+$/g, '') // 去结尾的副本编号 -1
    .trim();
  return base || null;
}

/** 生成人工待修改的随机占位（如 待定-a1b2）。 */
export function placeholderLabel(prefix = '待定'): string {
  return `${prefix}-${Math.random().toString(36).slice(2, 6)}`;
}

/** 从 GitHub 链接推导默认项目名，如 https://github.com/owner/repo -> repo */
export function repoNameFromUrl(url: string): string {
  try {
    const clean = url.trim().replace(/\.git$/, '').replace(/\/$/, '');
    const parts = clean.split('/').filter(Boolean);
    return parts[parts.length - 1] || 'repo';
  } catch {
    return 'repo';
  }
}

/**
 * 污点链规范化：审计技能应产出字符串（Schema 要求），但个别子智能体/主控偶尔会
 * 输出结构化数组（如 [{file,line,description}, ...]）。若不做处理直接 `String(value)`，
 * 数组会走 Array.prototype.toString —— 元素为普通对象时逐个变成 "[object Object]"，
 * 用逗号拼接后写入数据库，界面上就会显示成一串 "[object Object],[object Object],…"。
 * 这里在写库前统一把数组/对象转成可读的逐跳文本；已经是字符串但已被旧代码污染过的
 * （历史数据）同样识别并清空，而不是把损坏内容当正常文本继续展示。
 */
export function normalizeTaintChain(raw: unknown): string {
  if (raw == null) return '';
  if (typeof raw === 'string') {
    return raw.includes('[object Object]') ? '' : raw;
  }
  if (Array.isArray(raw)) {
    return raw
      .map((item, i) => {
        if (typeof item === 'string') return `${i + 1}. ${item}`;
        if (item && typeof item === 'object') {
          const o = item as Record<string, unknown>;
          const parts = [
            o.file ?? o.file_path,
            o.line != null ? `L${o.line}` : '',
            o.function ?? o.func,
            o.description ?? o.detail ?? o.code ?? o.snippet ?? o.action,
          ].filter((p) => p !== undefined && p !== null && p !== '');
          return `${i + 1}. ${parts.join(' · ')}`;
        }
        return `${i + 1}. ${String(item)}`;
      })
      .join('\n');
  }
  if (typeof raw === 'object') {
    try {
      return JSON.stringify(raw, null, 2);
    } catch {
      return '';
    }
  }
  return String(raw);
}

/** 生成 RFC 5987 兼容的 attachment Content-Disposition（支持中文文件名，避免 Express 500）。 */
export function contentDispositionAttachment(name: string, ext: string): string {
  const stem = String(name || 'report')
    .replace(/[^\w\u4e00-\u9fff.-]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 80);
  const base = stem || 'report';
  const filename = ext ? `${base}.${ext.replace(/^\./, '')}` : base;
  const ascii = filename.replace(/[^\x20-\x7E]/g, '_').replace(/"/g, '') || `report.${ext || 'bin'}`;
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(filename)}`;
}
