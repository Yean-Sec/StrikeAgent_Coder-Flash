import { Fragment, memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../lib/api';
import type { VulnRow, Severity } from '../lib/types';
import { SeverityBadge, RedTeamValueBadge } from '../components/Badges';
import { SEVERITY_ORDER, SEVERITY_LABEL, fmtDateMinute } from '../lib/format';
import './Vulnerabilities.css';

type SevFilter = Severity | 'all';
const PAGE_SIZE = 50;
// 前台 RCE 视图按项目折叠展示，量级不大，一次性拉满一页（服务端上限 200）后前端分组。
const FRONTEND_RCE_PAGE_SIZE = 200;
const EMPTY_COUNTS = { all: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, verified: 0, frontend_rce: 0 };

interface ProjectRceGroup {
  projectId: string;
  projectName: string;
  vulns: VulnRow[];
}

/** 按项目分组前台 RCE 漏洞，保持服务端已排好的「拿到时间从新到旧」顺序（以每组第一次出现为准）。 */
function groupByProject(rows: VulnRow[]): ProjectRceGroup[] {
  const order: string[] = [];
  const map = new Map<string, ProjectRceGroup>();
  for (const v of rows) {
    let g = map.get(v.project_id);
    if (!g) {
      g = { projectId: v.project_id, projectName: v.project_name, vulns: [] };
      map.set(v.project_id, g);
      order.push(v.project_id);
    }
    g.vulns.push(v);
  }
  return order.map((id) => map.get(id)!);
}

function topSeverityOf(vulns: VulnRow[]): Severity {
  for (const s of SEVERITY_ORDER) {
    if (vulns.some((v) => v.severity === s)) return s;
  }
  return 'info';
}

export default function Vulnerabilities() {
  const [vulns, setVulns] = useState<VulnRow[]>([]);
  const [total, setTotal] = useState(0);
  const [counts, setCounts] = useState<Record<string, number>>(EMPTY_COUNTS);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [searchParams] = useSearchParams();
  const initSev = (searchParams.get('severity') as SevFilter) || 'all';
  const [sevFilter, setSevFilter] = useState<SevFilter>(
    SEVERITY_ORDER.includes(initSev as Severity) || initSev === 'all' ? initSev : 'all'
  );
  const [onlyVerified, setOnlyVerified] = useState(searchParams.get('verified') === '1');
  const [onlyFrontendRce, setOnlyFrontendRce] = useState(searchParams.get('frontend_rce') === '1');
  const [catFilter, setCatFilter] = useState<string>(searchParams.get('category') || '');
  const [search, setSearch] = useState('');
  const [active, setActive] = useState<VulnRow | null>(null);
  const [expandedProjects, setExpandedProjects] = useState<Set<string>>(new Set());
  const navigate = useNavigate();
  const toggleProjectGroup = useCallback((projectId: string) => {
    setExpandedProjects((prev) => {
      const next = new Set(prev);
      if (next.has(projectId)) next.delete(projectId);
      else next.add(projectId);
      return next;
    });
  }, []);
  const selectVuln = useCallback((vuln: VulnRow) => {
    // 列表仅传输轻量字段；弹窗先即时打开，再按需补齐描述、代码和污点链。
    setActive(vuln);
    void api
      .getVulnerability(vuln.id)
      .then((detail) => {
        setActive((current) => (current?.id === detail.id ? detail : current));
      })
      .catch(() => {
        // 详情读取失败时保留轻量信息，不影响继续浏览列表。
      });
  }, []);
  const openProject = useCallback(
    (projectId: string) => navigate(`/projects/${projectId}`),
    [navigate]
  );

  // 服务端分页 + 过滤：任一条件变化即重新请求（搜索去抖 300ms）。
  const reqSeq = useRef(0);
  useEffect(() => {
    const seq = ++reqSeq.current;
    setLoading(true);
    const t = setTimeout(() => {
      api
        .allVulnerabilities({
          page: onlyFrontendRce ? 1 : page,
          pageSize: onlyFrontendRce ? FRONTEND_RCE_PAGE_SIZE : PAGE_SIZE,
          severity: sevFilter,
          verified: onlyVerified ? '1' : undefined,
          frontend_rce: onlyFrontendRce ? '1' : undefined,
          category: catFilter || undefined,
          search: search.trim() || undefined,
        })
        .then((res) => {
          if (seq !== reqSeq.current) return; // 丢弃过期响应
          setVulns(res.items);
          setTotal(res.total);
          setCounts(res.counts);
        })
        .catch(() => {})
        .finally(() => {
          if (seq === reqSeq.current) setLoading(false);
        });
    }, 300);
    return () => clearTimeout(t);
  }, [page, sevFilter, onlyVerified, onlyFrontendRce, catFilter, search]);

  // 过滤条件变化（非翻页）时回到第 1 页
  useEffect(() => {
    setPage(1);
  }, [sevFilter, onlyVerified, onlyFrontendRce, catFilter, search]);

  // 切换筛选条件时收起已展开的项目分组，避免残留展开态跨筛选串场。
  useEffect(() => {
    setExpandedProjects(new Set());
  }, [onlyFrontendRce, sevFilter, catFilter, search]);

  useEffect(() => {
    setOnlyVerified(searchParams.get('verified') === '1');
    setOnlyFrontendRce(searchParams.get('frontend_rce') === '1');
    const s = searchParams.get('severity') as SevFilter;
    if (SEVERITY_ORDER.includes(s as Severity) || s === 'all') setSevFilter(s);
    setCatFilter(searchParams.get('category') || '');
  }, [searchParams]);

  const filtered = vulns;
  const verifiedCount = counts.verified || 0;
  const frontendRceCount = counts.frontend_rce || 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const projectGroups = useMemo(
    () => (onlyFrontendRce ? groupByProject(filtered) : []),
    [onlyFrontendRce, filtered]
  );

  const heading = onlyFrontendRce
    ? '前台 RCE 漏洞'
    : onlyVerified
      ? '远程靶机验证漏洞'
      : '全部漏洞';
  const subtitle = onlyFrontendRce
    ? `远程靶机 HTTP 验证通过的 RCE：无需登录(none)或注册默认开放下普通用户(user)可触发，共 ${frontendRceCount} 个漏洞${
        frontendRceCount > FRONTEND_RCE_PAGE_SIZE ? `（仅展示最新 ${FRONTEND_RCE_PAGE_SIZE} 个）` : ''
      }，按项目折叠显示，点击项目行展开查看全部`
    : onlyVerified
      ? `远程靶机验证成功的真实漏洞，共 ${verifiedCount} 个`
      : `所有项目代码审计发现的漏洞，共 ${counts.all} 个`;

  return (
    <div className="vulns-page">
      <button className="back-link" onClick={() => navigate('/dashboard')}>
        <span className="back-link-arrow" aria-hidden="true">
          ←
        </span>
        返回数据大屏
      </button>
      <div className="page-head">
        <h1>{heading}</h1>
        <p>{subtitle}</p>
      </div>

      {(onlyVerified || onlyFrontendRce || catFilter) && (
        <div className="active-filters">
          {onlyFrontendRce && (
            <span className="filter-chip">
              前台 RCE
              <button onClick={() => setOnlyFrontendRce(false)} aria-label="清除">
                ✕
              </button>
            </span>
          )}
          {onlyVerified && (
            <span className="filter-chip">
              仅远程验证
              <button onClick={() => setOnlyVerified(false)} aria-label="清除">
                ✕
              </button>
            </span>
          )}
          {catFilter && (
            <span className="filter-chip">
              类型：{catFilter}
              <button onClick={() => setCatFilter('')} aria-label="清除">
                ✕
              </button>
            </span>
          )}
        </div>
      )}

      <div className="vulns-toolbar">
        <div className="sev-filter">
          <button
            className={'sfilter' + (sevFilter === 'all' ? ' active' : '')}
            onClick={() => setSevFilter('all')}
          >
            全部<span className="sfilter-count">{counts.all}</span>
          </button>
          {SEVERITY_ORDER.map((s) => (
            <button
              key={s}
              className={'sfilter sev-' + s + (sevFilter === s ? ' active' : '')}
              onClick={() => setSevFilter(s)}
            >
              {SEVERITY_LABEL[s]}
              <span className="sfilter-count">{counts[s] || 0}</span>
            </button>
          ))}
          <button
            className={'sfilter verified-filter' + (onlyFrontendRce ? ' active' : '')}
            onClick={() => setOnlyFrontendRce((v) => !v)}
            title="远程 HTTP 验证通过的 RCE：无权限(none) 或 注册默认开放+普通用户(user)"
          >
            前台 RCE<span className="sfilter-count">{frontendRceCount}</span>
          </button>
          <button
            className={'sfilter verified-filter' + (onlyVerified ? ' active' : '')}
            onClick={() => setOnlyVerified((v) => !v)}
            title="只看远程靶机验证成功的漏洞"
          >
            仅已验证<span className="sfilter-count">{verifiedCount}</span>
          </button>
        </div>
        <div className="search-box">
          <span className="search-icon">⌕</span>
          <input
            className="input search-input"
            placeholder="搜索标题 / 类型 / 文件 / 项目…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      <div className="card table-card">
        <table className="vuln-table">
          <thead>
            <tr>
              <th className="col-sev">等级</th>
              <th>漏洞</th>
              <th>类型</th>
              <th>项目</th>
              <th>位置</th>
              {onlyFrontendRce && <th className="col-rce-time">获得时间</th>}
            </tr>
          </thead>
          <tbody>
            {onlyFrontendRce
              ? projectGroups.map((g) =>
                  g.vulns.length > 1 ? (
                    <Fragment key={g.projectId}>
                      <ProjectGroupRow
                        group={g}
                        expanded={expandedProjects.has(g.projectId)}
                        onToggle={() => toggleProjectGroup(g.projectId)}
                        onOpenProject={openProject}
                      />
                      {expandedProjects.has(g.projectId) &&
                        g.vulns.map((v) => (
                          <VulnerabilityRow
                            key={v.id}
                            vuln={v}
                            onSelect={selectVuln}
                            onOpenProject={openProject}
                            showRceTime
                            nested
                          />
                        ))}
                    </Fragment>
                  ) : (
                    <VulnerabilityRow
                      key={g.vulns[0].id}
                      vuln={g.vulns[0]}
                      onSelect={selectVuln}
                      onOpenProject={openProject}
                      showRceTime
                    />
                  )
                )
              : filtered.map((v) => (
                  <VulnerabilityRow key={v.id} vuln={v} onSelect={selectVuln} onOpenProject={openProject} />
                ))}
            {!loading && filtered.length === 0 && (
              <tr>
                <td colSpan={onlyFrontendRce ? 6 : 5} className="empty-row">
                  {vulns.length === 0 ? '暂无漏洞数据' : '当前筛选条件下没有漏洞'}
                </td>
              </tr>
            )}
            {loading && (
              <tr>
                <td colSpan={onlyFrontendRce ? 6 : 5} className="empty-row">
                  加载中…
                </td>
              </tr>
            )}
          </tbody>
        </table>
        {total > 0 && !onlyFrontendRce && (
          <div className="pager">
            <span className="pager-info">
              共 {total} 个 · 第 {(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, total)} 个
            </span>
            <div className="pager-nav">
              <button
                className="pager-btn"
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                上一页
              </button>
              <span className="pager-cur">
                {page} / {totalPages}
              </span>
              <button
                className="pager-btn"
                disabled={page >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              >
                下一页
              </button>
            </div>
          </div>
        )}
      </div>

      {active && <VulnModal vuln={active} onClose={() => setActive(null)} />}
    </div>
  );
}

const ProjectGroupRow = memo(function ProjectGroupRow({
  group,
  expanded,
  onToggle,
  onOpenProject,
}: {
  group: ProjectRceGroup;
  expanded: boolean;
  onToggle: () => void;
  onOpenProject: (projectId: string) => void;
}) {
  const latestAt = Math.max(...group.vulns.map((v) => v.frontend_rce_at || 0));
  return (
    <tr onClick={onToggle} className={'vuln-tr group-tr' + (expanded ? ' expanded' : '')}>
      <td>
        <SeverityBadge severity={topSeverityOf(group.vulns)} />
      </td>
      <td className="vt-title">
        <span className="group-toggle-icon" aria-hidden="true">
          {expanded ? '▾' : '▸'}
        </span>
        共 {group.vulns.length} 个前台 RCE
      </td>
      <td className="muted">—</td>
      <td>
        <button
          className="vt-proj"
          onClick={(event) => {
            event.stopPropagation();
            onOpenProject(group.projectId);
          }}
        >
          {group.projectName}
        </button>
      </td>
      <td className="muted">—</td>
      <td className="muted mono vt-rce-time" title="该项目最新拿到前台 RCE 的时间">
        {fmtDateMinute(latestAt)}
      </td>
    </tr>
  );
});

const VulnerabilityRow = memo(function VulnerabilityRow({
  vuln,
  onSelect,
  onOpenProject,
  showRceTime,
  nested,
}: {
  vuln: VulnRow;
  onSelect: (vuln: VulnRow) => void;
  onOpenProject: (projectId: string) => void;
  showRceTime?: boolean;
  nested?: boolean;
}) {
  return (
    <tr onClick={() => onSelect(vuln)} className={'vuln-tr' + (nested ? ' vuln-tr-nested' : '')}>
      <td>
        <SeverityBadge severity={vuln.severity} />
      </td>
      <td className="vt-title">
        {vuln.title}
        {vuln.frontend_rce ? (
          <span className="verified-tag frontend-rce-tag">前台 RCE</span>
        ) : null}
        {vuln.verified ? <span className="verified-tag">已验证</span> : null}
        {vuln.regrade_value ? (
          <span className={'rtv-pill rtv-' + vuln.regrade_value}>
            实战 {vuln.regrade_value}
          </span>
        ) : null}
        {vuln.severity_original && vuln.severity_original !== vuln.severity ? (
          <span className="rtv-pill rtv-down" title="二次评级前等级">
            原 {SEVERITY_LABEL[vuln.severity_original]}
          </span>
        ) : null}
      </td>
      <td className="muted">{vuln.category || '—'}</td>
      <td>
        <button
          className="vt-proj"
          onClick={(event) => {
            event.stopPropagation();
            onOpenProject(vuln.project_id);
          }}
        >
          {vuln.project_name}
        </button>
      </td>
      <td className="muted ellipsis mono vt-loc" title={vuln.file_path}>
        {vuln.file_path}
        {vuln.line ? `:${vuln.line}` : ''}
      </td>
      {showRceTime && (
        <td className="muted mono vt-rce-time" title="拿到前台 RCE 的时间">
          {fmtDateMinute(vuln.frontend_rce_at)}
        </td>
      )}
    </tr>
  );
});

function VulnModal({ vuln, onClose }: { vuln: VulnRow; onClose: () => void }) {
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <SeverityBadge severity={vuln.severity} />
          {vuln.severity_original && vuln.severity_original !== vuln.severity && (
            <span className="sev-original" title="二次评级前的原始等级">
              原 {SEVERITY_LABEL[vuln.severity_original]}
            </span>
          )}
          {vuln.regrade_value && <RedTeamValueBadge value={vuln.regrade_value} />}
          <h2>{vuln.title}</h2>
          <button className="modal-close" onClick={onClose}>
            ✕
          </button>
        </div>
        <div className="modal-meta">
          <span>
            项目：<strong>{vuln.project_name}</strong>
          </span>
          {vuln.category && (
            <span>
              类别：<strong>{vuln.category}</strong>
            </span>
          )}
          {vuln.file_path && (
            <span>
              位置：
              <strong className="mono">
                {vuln.file_path}
                {vuln.line ? `:${vuln.line}` : ''}
              </strong>
            </span>
          )}
        </div>
        {vuln.regrade_reason && (
          <div className="modal-block regrade-block">
            <h4>
              红队实战二次评级
              {vuln.severity_original && vuln.severity_original !== vuln.severity && (
                <span className="regrade-change">
                  {SEVERITY_LABEL[vuln.severity_original]} → {SEVERITY_LABEL[vuln.severity]}
                </span>
              )}
            </h4>
            <p>{vuln.regrade_reason}</p>
          </div>
        )}
        {vuln.description && (
          <div className="modal-block">
            <h4>问题描述</h4>
            <p>{vuln.description}</p>
          </div>
        )}
        {vuln.taint_chain && (
          <div className="modal-block">
            <h4>污点链（Source→Sink）</h4>
            <pre className="code-block">{vuln.taint_chain}</pre>
          </div>
        )}
        {vuln.code_snippet && (
          <div className="modal-block">
            <h4>相关代码</h4>
            <pre className="code-block">{vuln.code_snippet}</pre>
          </div>
        )}
        {vuln.recommendation && (
          <div className="modal-block">
            <h4>修复建议</h4>
            <p>{vuln.recommendation}</p>
          </div>
        )}
      </div>
    </div>
  );
}
