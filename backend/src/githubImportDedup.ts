import db from './db';
import { parseOwnerRepo } from './githubMeta';
import type { Project } from './types';

export type GithubDuplicateKind = 'none' | 'project' | 'version' | 'batch';
export type GithubAuditScope = 'all' | 'new_projects_only' | 'new_versions_only';

export interface GithubRepoInput {
  url: string;
  projectName?: string;
}

export interface ParsedGithubRepo extends GithubRepoInput {
  owner: string;
  repo: string;
  canonicalUrl: string;
  systemName: string;
  repoKey: string;
  gitRef: string | null;
}

export interface GithubImportMatch {
  projectId: string;
  projectName: string;
  sourceVersion: string | null;
  gitRef: string | null;
  createdAt: number;
}

export interface GithubImportDuplicateItem {
  index: number;
  url: string;
  projectName?: string;
  owner: string;
  repo: string;
  gitRef: string | null;
  kind: GithubDuplicateKind;
  kindLabel: string;
  existingMatches: GithubImportMatch[];
}

export interface GithubImportPreview {
  items: GithubImportDuplicateItem[];
  summary: {
    total: number;
    newProjects: number;
    projectDuplicates: number;
    versionDuplicates: number;
    batchDuplicates: number;
    willAudit: Record<GithubAuditScope, number>;
  };
}

function normVer(s: string): string {
  return String(s || '')
    .trim()
    .replace(/^v/i, '')
    .toLowerCase();
}

/** 规整为 https://github.com/owner/repo，并解析可选 ref（tree/blob/releases/tag）。 */
export function parseGithubRepoUrl(raw: string): ParsedGithubRepo | null {
  let s = String(raw || '').trim();
  if (!s) return null;
  s = s.replace(/^["'`]+|["'`]+$/g, '');
  if (!/^https?:\/\//i.test(s)) {
    if (/^github\.com\//i.test(s)) s = 'https://' + s;
    else return null;
  }
  s = s.replace(/^http:\/\//i, 'https://');
  s = s.replace(/[)\]>,;'"`]+$/g, '');

  let gitRef: string | null = null;
  let owner = '';
  let repo = '';

  const tree = s.match(/github\.com\/([^/]+)\/([^/]+)\/(?:tree|blob)\/([^/?#]+)/i);
  if (tree) {
    owner = tree[1];
    repo = tree[2].replace(/\.git$/i, '');
    gitRef = decodeURIComponent(tree[3]);
  } else {
    const tag = s.match(/github\.com\/([^/]+)\/([^/]+)\/releases\/tag\/([^/?#]+)/i);
    if (tag) {
      owner = tag[1];
      repo = tag[2].replace(/\.git$/i, '');
      gitRef = decodeURIComponent(tag[3]);
    } else {
      const at = s.match(/github\.com\/([^/]+)\/([^@/?#]+)@([^/?#]+)/i);
      if (at) {
        owner = at[1];
        repo = at[2].replace(/\.git$/i, '');
        gitRef = decodeURIComponent(at[3]);
      } else {
        const or = parseOwnerRepo(s);
        if (!or) return null;
        owner = or.owner;
        repo = or.repo;
      }
    }
  }

  const canonicalUrl = `https://github.com/${owner}/${repo}`;
  const repoKey = `gh:${owner}/${repo}`.toLowerCase();
  return {
    url: canonicalUrl,
    canonicalUrl,
    owner,
    repo,
    systemName: repo,
    repoKey,
    gitRef,
  };
}

function versionsMatch(
  incomingRef: string | null,
  sourceVersion: string | null,
  gitRef: string | null
): boolean {
  if (!incomingRef) return false;
  const nr = normVer(incomingRef);
  if (!nr) return false;
  if (sourceVersion && normVer(sourceVersion) === nr) return true;
  if (gitRef && normVer(gitRef) === nr) return true;
  return false;
}

function kindLabel(kind: GithubDuplicateKind, gitRef: string | null): string {
  switch (kind) {
    case 'none':
      return '新项目（库中无同仓库记录）';
    case 'project':
      return gitRef
        ? '项目重复（同仓库已存在，指定版本与已有记录不同或未命中）'
        : '项目重复（同仓库已存在，导入后将解析为默认/最新版本）';
    case 'version':
      return '版本重复（同仓库且同版本已审计）';
    case 'batch':
      return '本批重复（同一地址在本列表中已出现）';
    default:
      return kind;
  }
}

function loadGithubProjects(): Project[] {
  return db
    .prepare("SELECT * FROM projects WHERE source_type = 'github'")
    .all() as Project[];
}

function repoKeyOfProject(p: Project): string | null {
  const or = parseOwnerRepo(p.source_ref);
  return or ? `gh:${or.owner}/${or.repo}`.toLowerCase() : null;
}

export function shouldIncludeInScope(kind: GithubDuplicateKind, scope: GithubAuditScope): boolean {
  if (kind === 'batch') return false;
  if (scope === 'all') return true;
  if (scope === 'new_projects_only') return kind === 'none';
  if (scope === 'new_versions_only') return kind === 'none' || kind === 'project';
  return true;
}

export function analyzeGithubImport(repos: GithubRepoInput[]): GithubImportPreview {
  const existing = loadGithubProjects();
  const byRepoKey = new Map<string, Project[]>();
  for (const p of existing) {
    const key = repoKeyOfProject(p);
    if (!key) continue;
    if (!byRepoKey.has(key)) byRepoKey.set(key, []);
    byRepoKey.get(key)!.push(p);
  }

  const batchSeen = new Set<string>();
  const items: GithubImportDuplicateItem[] = [];

  repos.forEach((input, index) => {
    const parsed = parseGithubRepoUrl(input.url);
    if (!parsed) {
      items.push({
        index,
        url: String(input.url || '').trim(),
        projectName: input.projectName,
        owner: '',
        repo: '',
        gitRef: null,
        kind: 'none',
        kindLabel: '无法解析的 GitHub 地址（提交时将跳过）',
        existingMatches: [],
      });
      return;
    }

    const batchKey = `${parsed.repoKey}|${parsed.gitRef ? normVer(parsed.gitRef) : ''}`;
    let kind: GithubDuplicateKind = 'none';
    const matches = (byRepoKey.get(parsed.repoKey) || []).map((p) => ({
      projectId: p.id,
      projectName: p.project_name,
      sourceVersion: p.source_version,
      gitRef: p.git_ref,
      createdAt: p.created_at,
    }));

    if (batchSeen.has(batchKey)) {
      kind = 'batch';
    } else {
      batchSeen.add(batchKey);
      if (matches.length === 0) {
        kind = 'none';
      } else if (parsed.gitRef && matches.some((m) => versionsMatch(parsed.gitRef, m.sourceVersion, m.gitRef))) {
        kind = 'version';
      } else {
        kind = 'project';
      }
    }

    items.push({
      index,
      url: parsed.canonicalUrl,
      projectName: input.projectName,
      owner: parsed.owner,
      repo: parsed.repo,
      gitRef: parsed.gitRef,
      kind,
      kindLabel: kindLabel(kind, parsed.gitRef),
      existingMatches: matches,
    });
  });

  const summary = {
    total: items.length,
    newProjects: items.filter((i) => i.kind === 'none').length,
    projectDuplicates: items.filter((i) => i.kind === 'project').length,
    versionDuplicates: items.filter((i) => i.kind === 'version').length,
    batchDuplicates: items.filter((i) => i.kind === 'batch').length,
    willAudit: {
      all: items.filter((i) => shouldIncludeInScope(i.kind, 'all')).length,
      new_projects_only: items.filter((i) => shouldIncludeInScope(i.kind, 'new_projects_only')).length,
      new_versions_only: items.filter((i) => shouldIncludeInScope(i.kind, 'new_versions_only')).length,
    },
  };

  return { items, summary };
}

export function filterGithubReposForScope(
  repos: GithubRepoInput[],
  scope: GithubAuditScope
): { repos: GithubRepoInput[]; skipped: GithubImportDuplicateItem[] } {
  const preview = analyzeGithubImport(repos);
  const kept: GithubRepoInput[] = [];
  const skipped: GithubImportDuplicateItem[] = [];
  for (let i = 0; i < repos.length; i++) {
    const item = preview.items[i];
    const input = repos[i];
    if (!item || !input?.url?.trim()) continue;
    if (!parseGithubRepoUrl(input.url)) {
      skipped.push(
        item || {
          index: i,
          url: input.url,
          kind: 'batch',
          kindLabel: '无法解析',
          existingMatches: [],
          owner: '',
          repo: '',
          gitRef: null,
        }
      );
      continue;
    }
    if (shouldIncludeInScope(item.kind, scope)) kept.push(input);
    else skipped.push(item);
  }
  return { repos: kept, skipped };
}

export function parseGithubRepoForCreate(raw: string): ParsedGithubRepo | null {
  return parseGithubRepoUrl(raw);
}
