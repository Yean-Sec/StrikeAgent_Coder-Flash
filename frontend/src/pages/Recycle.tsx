import { useCallback, useEffect, useRef, useState } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { api } from '../lib/api';
import type { DeletedProject } from '../lib/types';
import { fmtDateMinute } from '../lib/format';
import { useDebouncedValue } from '../hooks/useDebouncedValue';
import './Recycle.css';

const REASON_LABEL: Record<string, string> = {
  manual: '手动删除',
  bulk: '批量删除',
  auto_non_web: '判定非 Web 清理',
};
const PAGE_SIZE = 50;

function reasonLabel(r: string): string {
  return REASON_LABEL[r] || r || '删除';
}

function webLabel(v: number | null): string {
  if (v === 1) return '含 Web 端';
  if (v === 0) return '无 Web 端';
  return '未判定';
}

export default function Recycle() {
  const [rows, setRows] = useState<DeletedProject[]>([]);
  const [reportedTotal, setReportedTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(1);
  const scrollRef = useRef<HTMLDivElement>(null);
  const debouncedQuery = useDebouncedValue(query.trim(), 250);

  const load = useCallback(() => {
    setLoading(true);
    api
      .getRecyclePage({
        page,
        pageSize: PAGE_SIZE,
        search: debouncedQuery || undefined,
      })
      .then((response) => {
        setRows(response.items);
        setReportedTotal(response.total);
      })
      .catch(() => {
        setRows([]);
        setReportedTotal(0);
      })
      .finally(() => setLoading(false));
  }, [debouncedQuery, page]);

  useEffect(() => {
    load();
  }, [load]);

  const clearAll = async () => {
    const count = Math.max(reportedTotal, rows.length);
    if (!confirm(`确认清空回收站的 ${count} 条删除记录？（仅清除记录，不影响已删项目）`)) return;
    await api.clearRecycle();
    load();
  };

  const totalPages = Math.max(1, Math.ceil(reportedTotal / PAGE_SIZE));
  const pageRows = rows;
  const virtualizer = useVirtualizer({
    count: pageRows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 50,
    overscan: 6,
    getItemKey: (index) => pageRows[index]?.id ?? index,
  });

  useEffect(() => {
    setPage(1);
  }, [debouncedQuery]);

  useEffect(() => {
    setPage((current) => Math.min(current, totalPages));
  }, [totalPages]);

  useEffect(() => {
    virtualizer.scrollToOffset(0);
  }, [page, debouncedQuery, virtualizer]);

  const isUrl = (s: string) => /^https?:\/\//i.test(s);
  const recordTotal = Math.max(reportedTotal, rows.length);

  return (
    <div className="recycle-page">
      <div className="page-head">
        <div>
          <h1>回收站</h1>
          <p>记录所有已删除项目（GitHub 记链接、压缩包记文件名）。仅留痕，不支持还原。</p>
        </div>
        <div className="recycle-head-actions">
          <input
            className="recycle-search"
            placeholder="搜索项目名 / 来源…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <button className="btn btn-secondary" onClick={load}>
            刷新
          </button>
          <button
            className="btn btn-danger"
            onClick={clearAll}
            disabled={recordTotal === 0}
            title={recordTotal === 0 ? '暂无记录' : '清空全部删除记录'}
          >
            清空记录
          </button>
        </div>
      </div>

      <div className="recycle-count">
        {debouncedQuery
          ? `筛选到 ${recordTotal} 条`
          : `共 ${recordTotal} 条删除记录`}
      </div>

      {loading ? (
        <div className="recycle-empty">加载中…</div>
      ) : rows.length === 0 ? (
        <div className="recycle-empty">暂无删除记录</div>
      ) : (
        <div className="recycle-table-wrap">
          <div className="recycle-table-head" role="row">
            <span role="columnheader">项目名</span>
            <span role="columnheader">来源</span>
            <span role="columnheader">Web 端</span>
            <span role="columnheader">漏洞数</span>
            <span role="columnheader">删除原因</span>
            <span role="columnheader">删除时间</span>
          </div>
          <div ref={scrollRef} className="recycle-table-body" role="rowgroup">
            <div
              className="recycle-table-virtual"
              style={{ height: virtualizer.getTotalSize() }}
            >
              {virtualizer.getVirtualItems().map((virtualRow) => {
                const row = pageRows[virtualRow.index];
                return (
                  <div
                    key={virtualRow.key}
                    ref={virtualizer.measureElement}
                    data-index={virtualRow.index}
                    className="recycle-table-row"
                    role="row"
                    style={{ transform: `translateY(${virtualRow.start}px)` }}
                  >
                    <span role="cell" className="rc-name" title={row.project_name}>
                      {row.project_name}
                    </span>
                    <span role="cell" className="rc-source" title={row.source_link}>
                      {isUrl(row.source_link) ? (
                        <a href={row.source_link} target="_blank" rel="noreferrer">
                          {row.source_link}
                        </a>
                      ) : (
                        <span className="rc-archive">{row.source_link || '—'}</span>
                      )}
                    </span>
                    <span role="cell">
                      <span className={'rc-web rc-web-' + (row.has_web ?? 'null')}>
                        {webLabel(row.has_web)}
                      </span>
                    </span>
                    <span role="cell" className="rc-num">{row.vuln_count}</span>
                    <span role="cell" className="rc-reason-cell">
                      <span className={'rc-reason rc-reason-' + row.reason}>
                        {reasonLabel(row.reason)}
                      </span>
                      {row.detail ? (
                        <span className="rc-detail" title={row.detail}> · {row.detail}</span>
                      ) : null}
                    </span>
                    <span role="cell" className="rc-time">{fmtDateMinute(row.deleted_at)}</span>
                  </div>
                );
              })}
            </div>
          </div>
          {totalPages > 1 && (
            <div className="recycle-pager">
              <span>
                第 {(page - 1) * PAGE_SIZE + 1}–
                {Math.min(page * PAGE_SIZE, reportedTotal)} / {reportedTotal} 条
              </span>
              <div className="recycle-pager-actions">
                <button
                  className="btn btn-secondary"
                  disabled={page <= 1}
                  onClick={() => setPage((current) => Math.max(1, current - 1))}
                >
                  上一页
                </button>
                <span>{page} / {totalPages}</span>
                <button
                  className="btn btn-secondary"
                  disabled={page >= totalPages}
                  onClick={() => setPage((current) => Math.min(totalPages, current + 1))}
                >
                  下一页
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
