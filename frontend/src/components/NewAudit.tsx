import { useMemo, useRef, useState } from 'react';
import { api } from '../lib/api';
import type { AuditOptions, GithubAuditScope, GithubImportPreview } from '../lib/api';
import { SUBAGENT_TRAIT_HINT, subagentCountForLanguage } from '../lib/subagents';

const AUDIT_LANGUAGES: { id: string; label: string }[] = [
  { id: 'java', label: 'Java' },
  { id: 'go', label: 'Go' },
  { id: 'python', label: 'Python' },
  { id: 'php', label: 'PHP' },
  { id: 'jsts', label: 'JavaScript / TypeScript' },
  { id: 'rust', label: 'Rust' },
  { id: 'ruby', label: 'Ruby' },
  { id: 'csharp', label: 'C# / .NET' },
  { id: 'c', label: 'C' },
  { id: 'cpp', label: 'C++' },
  { id: 'solidity', label: 'Solidity' },
];

type Tab = 'upload' | 'github';

type RepoEntry = { url: string; projectName?: string };

function dequote(s: string): string {
  return s.replace(/^["'`]+|["'`]+$/g, '').trim();
}

function isGithubUrl(s: string): boolean {
  return /(?:https?:\/\/)?(?:www\.)?github\.com\/[\w.-]+\/[\w.-]+/i.test(
    dequote(String(s || '').trim())
  );
}

// 规整 GitHub 地址；保留 /tree/、/blob/、/releases/tag/ 中的版本 ref
function normalizeUrl(u: string): string {
  let s = dequote(String(u || '').trim());
  if (!s) return '';
  s = s.replace(/^www\./i, 'https://www.');
  if (!/^https?:\/\//i.test(s)) {
    if (/^github\.com\//i.test(s)) s = 'https://' + s;
    else return '';
  }
  s = s.replace(/^http:\/\//i, 'https://');
  s = s.replace(/[)\]>,;'"`]+$/g, '');
  s = s.replace(/\.git(\/|$)/i, '$1');
  s = s.replace(/\/+$/g, '');
  if (!/github\.com\/[\w.-]+\/[\w.-]+/i.test(s)) return '';
  return s;
}

// 智能解析粘贴内容：兼容引号、逗号、方括号、缩进、"名称,地址" 自定义命名等
export function parseGithubInput(text: string): RepoEntry[] {
  const entries: RepoEntry[] = [];
  const seen = new Set<string>();
  const add = (url: string, name?: string) => {
    const n = normalizeUrl(url);
    if (!n) return;
    const key = n.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    entries.push(name ? { url: n, projectName: name } : { url: n });
  };

  for (const rawLine of text.split('\n')) {
    let s = rawLine
      .trim()
      .replace(/^[\s>*\-•]+/, '')
      .replace(/[;,]\s*$/, '')
      .trim();
    if (!s || /^[[\]{}()]+$/.test(s)) continue;

    // 形式：名称,地址（自定义项目名）
    const ci = s.indexOf(',');
    if (ci !== -1) {
      const left = dequote(s.slice(0, ci).trim());
      const right = dequote(s.slice(ci + 1).trim());
      if (left && !/^https?:/i.test(left) && !isGithubUrl(left) && isGithubUrl(right)) {
        add(right, left);
        continue;
      }
    }

    const m = s.match(/(?:https?:\/\/)?(?:www\.)?github\.com\/[^\s"'`,)\]]+/i);
    if (m) {
      add(m[0]);
      continue;
    }
    const d = dequote(s);
    if (isGithubUrl(d)) add(d);
  }
  return entries;
}

function serializeRepos(repos: RepoEntry[]): string {
  return repos.map((r) => (r.projectName ? `${r.projectName},${r.url}` : r.url)).join('\n');
}

const SCOPE_OPTIONS: { id: GithubAuditScope; title: string; desc: string }[] = [
  {
    id: 'all',
    title: '审计全部导入项',
    desc: '包含新项目、项目重复与版本重复；仅跳过本批列表内的重复地址',
  },
  {
    id: 'new_versions_only',
    title: '仅审计「项目重复但版本不重复」+ 新项目',
    desc: '跳过库中已有同仓库同版本的记录；同仓库的新版本或未指定版本仍会审计',
  },
  {
    id: 'new_projects_only',
    title: '仅审计项目不重复',
    desc: '只创建库中从未出现过的 GitHub 仓库',
  },
];

function kindBadgeClass(kind: string): string {
  if (kind === 'none') return 'gh-dup-none';
  if (kind === 'project') return 'gh-dup-project';
  if (kind === 'version') return 'gh-dup-version';
  return 'gh-dup-batch';
}

function GithubDuplicateModal({
  preview,
  scope,
  onScope,
  onConfirm,
  onClose,
  busy,
}: {
  preview: GithubImportPreview;
  scope: GithubAuditScope;
  onScope: (s: GithubAuditScope) => void;
  onConfirm: () => void;
  onClose: () => void;
  busy: boolean;
}) {
  const { summary } = preview;
  const hasDup =
    summary.projectDuplicates + summary.versionDuplicates + summary.batchDuplicates > 0;

  return (
    <div className="del-overlay" onClick={onClose}>
      <div className="gh-dedup-modal" onClick={(e) => e.stopPropagation()}>
        <h3>检测到重复导入</h3>
        <p className="gh-dedup-sub">
          共 {summary.total} 个地址：新项目 {summary.newProjects}、项目重复 {summary.projectDuplicates}
          、版本重复 {summary.versionDuplicates}
          {summary.batchDuplicates ? `、本批重复 ${summary.batchDuplicates}` : ''}。
          请选择要实际发起审计的范围。
        </p>

        <div className="gh-dedup-list">
          {preview.items.map((item) => (
            <div key={item.index} className="gh-dedup-row">
              <span className={'gh-dup-badge ' + kindBadgeClass(item.kind)}>{item.kindLabel}</span>
              <div className="gh-dedup-main">
                <strong>
                  {item.owner && item.repo ? `${item.owner}/${item.repo}` : item.url}
                  {item.gitRef ? `@${item.gitRef}` : ''}
                </strong>
                {item.projectName && <span className="muted"> · {item.projectName}</span>}
                {item.existingMatches.length > 0 && (
                  <div className="gh-dedup-matches">
                    已有：
                    {item.existingMatches.map((m) => (
                      <span key={m.projectId} className="gh-dedup-match">
                        {m.projectName}
                        {m.sourceVersion ? ` (${m.sourceVersion})` : ''}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>

        {hasDup && (
          <div className="gh-dedup-scopes">
            {SCOPE_OPTIONS.map((opt) => (
              <label key={opt.id} className={'gh-scope-opt' + (scope === opt.id ? ' on' : '')}>
                <input
                  type="radio"
                  name="auditScope"
                  checked={scope === opt.id}
                  onChange={() => onScope(opt.id)}
                />
                <div>
                  <strong>{opt.title}</strong>
                  <span>
                    {opt.desc}（将审计 {preview.summary.willAudit[opt.id]} 个）
                  </span>
                </div>
              </label>
            ))}
          </div>
        )}

        <div className="bv-actions">
          <button className="btn btn-secondary" onClick={onClose} disabled={busy}>
            取消
          </button>
          <button className="btn btn-primary" onClick={onConfirm} disabled={busy || preview.summary.willAudit[scope] === 0}>
            {busy
              ? '提交中…'
              : `确认审计 (${preview.summary.willAudit[scope]})`}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function NewAudit({ onCreated }: { onCreated: () => void }) {
  const [tab, setTab] = useState<Tab>('upload');
  const [files, setFiles] = useState<{ file: File; name: string }[]>([]);
  const [githubText, setGithubText] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const [dupPreview, setDupPreview] = useState<GithubImportPreview | null>(null);
  const [auditScope, setAuditScope] = useState<GithubAuditScope>('new_versions_only');
  const fileInput = useRef<HTMLInputElement>(null);
  // 审计流程选项（逐项目配置）。验证其他版本已从 Flash 产品面移除，始终关闭。
  const [options, setOptions] = useState<AuditOptions>({
    auto_verify: true,
    verify_history: false,
    ai_dedup: true,
    ai_regrade: true,
    verify_runtime: 'full',
  });
  const setOpt = (k: 'ai_dedup' | 'ai_regrade', v: boolean) =>
    setOptions((prev) => ({ ...prev, [k]: v }));
  const setVerifyRuntime = (runtime: 'full' | 'none') =>
    setOptions((prev) => ({
      ...prev,
      verify_runtime: runtime,
      auto_verify: runtime !== 'none',
    }));
  const submitOptions = (): AuditOptions => ({
    ...options,
    verify_runtime: options.verify_runtime === 'none' ? 'none' : 'full',
    auto_verify: options.verify_runtime !== 'none',
    verify_history: false,
  });
  const [auditLanguage, setAuditLanguage] = useState('');

  const onFiles = (list: FileList | null) => {
    if (!list) return;
    const arr = Array.from(list).map((file) => ({
      file,
      name: file.name.replace(/\.zip$/i, ''),
    }));
    setFiles((prev) => [...prev, ...arr]);
  };

  const submitUpload = async () => {
    if (files.length === 0) return;
    if (!auditLanguage) {
      setMsg('请先选择审计语言（11 选 1）');
      return;
    }
    setBusy(true);
    setMsg('');
    try {
      const res = await api.uploadProjects(
        files.map((f) => f.file),
        files.map((f) => f.name),
        submitOptions(),
        auditLanguage
      );
      setFiles([]);
      if (fileInput.current) fileInput.current.value = '';
      setMsg(`已创建 ${res.created.length} 个审计任务`);
      onCreated();
    } catch (e: any) {
      const raw = e?.response?.data?.error || e.message || String(e);
      const hint =
        /network error|timeout|ECONNREFUSED|ERR_NETWORK/i.test(raw)
          ? '（后端未响应，请确认终端里 npm run dev / start:web 正在运行且后端端口可用）'
          : '';
      setMsg('上传失败：' + raw + hint);
    } finally {
      setBusy(false);
    }
  };

  const parsedRepos = useMemo(() => parseGithubInput(githubText), [githubText]);

  const tidyGithub = () => {
    const cleaned = serializeRepos(parsedRepos);
    if (cleaned && cleaned !== githubText.trim()) setGithubText(cleaned);
  };

  const finalizeGithub = async (repos: RepoEntry[], scope: GithubAuditScope) => {
    const res = await api.githubProjects(repos, submitOptions(), scope, auditLanguage);
    const skip = res.skipped?.length ? `，跳过 ${res.skipped.length} 个` : '';
    setGithubText('');
    setDupPreview(null);
    setMsg(
      res.created.length
        ? `已创建 ${res.created.length} 个审计任务${skip}`
        : `未创建新任务${skip || '（所选范围内无待审计项）'}`
    );
    if (res.created.length > 0) onCreated();
  };

  const submitGithub = async (scope?: GithubAuditScope) => {
    const repos = parsedRepos;
    if (repos.length === 0) {
      setMsg('未识别到有效的 GitHub 仓库地址');
      return;
    }
    if (!auditLanguage) {
      setMsg('请先选择审计语言（11 选 1）');
      return;
    }
    setBusy(true);
    setMsg('');
    try {
      if (scope) {
        await finalizeGithub(repos, scope);
        return;
      }
      const preview = await api.githubPreview(repos);
      const hasDup =
        preview.summary.projectDuplicates +
          preview.summary.versionDuplicates +
          preview.summary.batchDuplicates >
        0;
      if (hasDup) {
        setAuditScope('new_versions_only');
        setDupPreview(preview);
        setBusy(false);
        return;
      }
      await finalizeGithub(repos, 'all');
    } catch (e: any) {
      setMsg('提交失败：' + (e?.response?.data?.error || e.message));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card new-audit">
      <div className="audit-tabs">
        <button
          className={'audit-tab' + (tab === 'upload' ? ' active' : '')}
          onClick={() => setTab('upload')}
        >
          上传压缩包
        </button>
        <button
          className={'audit-tab' + (tab === 'github' ? ' active' : '')}
          onClick={() => setTab('github')}
        >
          GitHub 地址
        </button>
      </div>

      <div className="audit-options-panel">
        <div className="audit-options-title">审计流程选项（本次新建生效）</div>
        <div className="audit-options-grid">
          <div className={'opt-row' + (auditLanguage ? ' on' : '')}>
            <div className="opt-text">
              <strong>审计语言</strong>
              <span>
                {auditLanguage
                  ? `按 ${AUDIT_LANGUAGES.find((l) => l.id === auditLanguage)?.label || auditLanguage} 特性并发 ${subagentCountForLanguage(auditLanguage)} 路专项：${SUBAGENT_TRAIT_HINT[auditLanguage] || '该语言高危方向'}`
                  : '每个项目只审一种语言；后端按该语言特性最多派 4 路专项智能体，CWE 面合并进同一路'}
              </span>
            </div>
            <select
              className="input"
              value={auditLanguage}
              onChange={(e) => setAuditLanguage(e.target.value)}
              aria-label="审计语言"
            >
              <option value="">请选择语言</option>
              {AUDIT_LANGUAGES.map((l) => (
                <option key={l.id} value={l.id}>
                  {l.label}
                </option>
              ))}
            </select>
          </div>
          <div className="opt-row opt-runtime-span">
            <div className="opt-text">
              <strong>远程验证</strong>
              <span>
                远程验证只在 Compose 整站上打 HTTP。默认完整靶机；选「仅代码审计」则审完即止。
              </span>
            </div>
            <div className="opt-runtime-choices" role="radiogroup" aria-label="远程验证形态">
              {(
                [
                  {
                    id: 'full' as const,
                    title: '完整靶机',
                    desc: 'Compose 整站 + HTTP + 组合链',
                  },
                  {
                    id: 'none' as const,
                    title: '仅代码审计',
                    desc: '审完即止，不入队远程验证',
                  },
                ]
              ).map((c) => (
                <button
                  key={c.id}
                  type="button"
                  className={'opt-runtime-card' + (options.verify_runtime === c.id ? ' on' : '')}
                  role="radio"
                  aria-checked={options.verify_runtime === c.id}
                  onClick={() => setVerifyRuntime(c.id)}
                >
                  <strong>{c.title}</strong>
                  <span>{c.desc}</span>
                </button>
              ))}
            </div>
          </div>
          <div className={'opt-row' + (options.ai_dedup ? ' on' : '')}>
            <div className="opt-text">
              <strong>AI 智能去重</strong>
              <span>代码级验证前合并不同子智能体对同一漏洞的重复上报</span>
            </div>
            <label className="switch">
              <input
                type="checkbox"
                checked={options.ai_dedup}
                onChange={(e) => setOpt('ai_dedup', e.target.checked)}
              />
              <span className="track" />
            </label>
          </div>
          <div className={'opt-row' + (options.ai_regrade ? ' on' : '')}>
            <div className="opt-text">
              <strong>红队二次评级</strong>
              <span>代码级验证之后按真实利用价值校准严重度；每路 10 个洞、最多 10 路同时评（一轮最多 100 个）</span>
            </div>
            <label className="switch">
              <input
                type="checkbox"
                checked={options.ai_regrade}
                onChange={(e) => setOpt('ai_regrade', e.target.checked)}
              />
              <span className="track" />
            </label>
          </div>
        </div>
      </div>

      {tab === 'upload' ? (
        <div className="audit-body">
          <div
            className="dropzone"
            onClick={() => fileInput.current?.click()}
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => {
              e.preventDefault();
              onFiles(e.dataTransfer.files);
            }}
          >
            <span className="spark" />
            <div>
              <strong>点击选择</strong> 或拖拽 .zip 文件到此处
              <div className="muted">仅支持 Zip 上传；GitHub 请用旁边标签页克隆</div>
            </div>
            <input
              ref={fileInput}
              type="file"
              accept=".zip"
              multiple
              hidden
              onChange={(e) => onFiles(e.target.files)}
            />
          </div>

          {files.length > 0 && (
            <div className="file-list">
              {files.map((f, i) => (
                <div key={i} className="file-row">
                  <span className="file-ext">
                    ZIP
                  </span>
                  <span className="file-orig ellipsis" title={f.file.name}>
                    {f.file.name}
                  </span>
                  <input
                    className="input file-name"
                    placeholder="项目名称（可自定义）"
                    value={f.name}
                    onChange={(e) =>
                      setFiles((prev) =>
                        prev.map((x, idx) =>
                          idx === i ? { ...x, name: e.target.value } : x
                        )
                      )
                    }
                  />
                  <button
                    className="btn btn-ghost"
                    onClick={() => setFiles((prev) => prev.filter((_, idx) => idx !== i))}
                  >
                    移除
                  </button>
                </div>
              ))}
            </div>
          )}

          <div className="audit-actions">
            <button
              className="btn btn-primary"
              disabled={busy || files.length === 0 || !auditLanguage}
              onClick={submitUpload}
            >
              {busy ? '提交中…' : `开始审计 (${files.length})`}
            </button>
            {msg && <span className="audit-msg">{msg}</span>}
          </div>
        </div>
      ) : (
        <div className="audit-body">
          <textarea
            className="textarea"
            rows={6}
            placeholder={
              '每行一个 GitHub 仓库地址，粘贴带引号/逗号/缩进的列表也会自动整理，例如：\nhttps://github.com/owner/repo\nhttps://github.com/owner/repo/tree/v1.0.0\n也可指定项目名（名称,地址）：\n我的项目,https://github.com/owner/repo'
            }
            value={githubText}
            onChange={(e) => setGithubText(e.target.value)}
            onBlur={tidyGithub}
          />
          <div className="audit-actions">
            <button
              className="btn btn-primary"
              disabled={busy || parsedRepos.length === 0 || !auditLanguage}
              onClick={() => submitGithub()}
            >
              {busy ? '提交中…' : `开始审计${parsedRepos.length ? ` (${parsedRepos.length})` : ''}`}
            </button>
            <button
              className="btn btn-secondary"
              disabled={busy || parsedRepos.length === 0}
              onClick={tidyGithub}
              title="清洗并去重为标准地址列表"
            >
              智能整理
            </button>
            {githubText.trim() && (
              <span className="audit-hint">已识别 {parsedRepos.length} 个仓库</span>
            )}
            {msg && <span className="audit-msg">{msg}</span>}
          </div>
        </div>
      )}

      {dupPreview && (
        <GithubDuplicateModal
          preview={dupPreview}
          scope={auditScope}
          onScope={setAuditScope}
          onClose={() => !busy && setDupPreview(null)}
          onConfirm={() => submitGithub(auditScope)}
          busy={busy}
        />
      )}
    </div>
  );
}
