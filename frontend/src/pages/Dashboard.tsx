import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../lib/api';
import { wsClient } from '../lib/ws';
import type { DashboardData, Severity } from '../lib/types';
import { SEVERITY_LABEL, SEVERITY_ORDER } from '../lib/format';
import Counter from '../components/Counter';
import ReactECharts from '../components/EChart';
import './Dashboard.css';

const SEV_HEX: Record<Severity, string> = {
  critical: '#c64545',
  high: '#cc785c',
  medium: '#d4a017',
  low: '#5db8a6',
  info: '#8e8b82',
};

// 漏洞等级中文标签 → severity key 反查，用于图表点击下钻
const LABEL_TO_SEV: Record<string, Severity> = Object.fromEntries(
  SEVERITY_ORDER.map((s) => [SEVERITY_LABEL[s], s])
) as Record<string, Severity>;

const EMPTY_SEV: Record<Severity, number> = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
};
const EMPTY_CATEGORIES: Record<string, number> = {};
const BAR_SEV = SEVERITY_ORDER.filter((s) => s !== 'info');
const PIE_CHART_STYLE = { height: 240 };
const VERIFIED_CHART_STYLE = { height: 280 };

function topCategories(values: Record<string, number>) {
  return Object.entries(values)
    .filter(([, value]) => value > 0)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([name, value]) => ({ name, value }));
}

function typeBarOption(entries: { name: string; value: number }[], color: string) {
  return {
    grid: { left: 8, right: 30, top: 8, bottom: 8, containLabel: true },
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    xAxis: {
      type: 'value',
      minInterval: 1,
      splitLine: { lineStyle: { color: '#ebe6df' } },
      axisLabel: { color: '#6c6a64' },
    },
    yAxis: {
      type: 'category',
      inverse: true,
      data: entries.map((entry) => entry.name),
      axisLine: { lineStyle: { color: '#e6dfd8' } },
      axisTick: { show: false },
      axisLabel: { color: '#6c6a64', width: 130, overflow: 'truncate' },
    },
    series: [
      {
        type: 'bar',
        barWidth: 14,
        itemStyle: { color, borderRadius: [0, 6, 6, 0] },
        label: { show: true, position: 'right', color: '#3a3833', fontWeight: 600 },
        data: entries.map((entry) => entry.value),
      },
    ],
  };
}

const typeChartHeight = (count: number) => Math.max(180, count * 34 + 24);

export default function Dashboard() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loadError, setLoadError] = useState('');
  const navigate = useNavigate();
  const timer = useRef<number | null>(null);
  const refreshTimer = useRef<number | null>(null);
  const loading = useRef(false);
  const dataSignature = useRef('');

  const load = useCallback(async () => {
    // 定时刷新与 WS 通知可能同时到达；禁止堆积多个昂贵的聚合请求。
    if (loading.current) return;
    loading.current = true;
    try {
      const next = await api.dashboard();
      setLoadError('');
      const signature = JSON.stringify(next);
      if (signature !== dataSignature.current) {
        dataSignature.current = signature;
        setData(next);
      }
    } catch (error: any) {
      setLoadError(error?.response?.data?.error || error?.message || '大屏数据加载失败');
      /* 保留上一次成功数据 */
    } finally {
      loading.current = false;
    }
  }, []);

  useEffect(() => {
    load();
    // 大屏统计是全库聚合，10 秒轮询足够及时；关键状态变化仍由 WS 触发尾随刷新。
    timer.current = window.setInterval(load, 10_000);
    const unsub = wsClient.subscribe((msg) => {
      if (msg.type !== 'project_status' && msg.type !== 'monitor_triggered') return;
      // 一次审计会连续产生大量状态消息，合并成静默 800ms 后的一次请求。
      if (refreshTimer.current) clearTimeout(refreshTimer.current);
      refreshTimer.current = window.setTimeout(() => {
        refreshTimer.current = null;
        load();
      }, 800);
    }, { scope: 'dashboard' });
    return () => {
      if (timer.current) clearInterval(timer.current);
      if (refreshTimer.current) clearTimeout(refreshTimer.current);
      unsub();
    };
  }, [load]);

  const sev = data?.severityTotals || EMPTY_SEV;
  const verifiedSev = data?.verifiedSeverityTotals || EMPTY_SEV;

  // 漏洞类型分布：两个独立条形图，分别取各自数量最多的前 8 类
  const auditCats = useMemo(
    () => topCategories(data?.auditCategoryTotals || EMPTY_CATEGORIES),
    [data?.auditCategoryTotals]
  );
  const verifiedCats = useMemo(
    () => topCategories(data?.verifiedCategoryTotals || EMPTY_CATEGORIES),
    [data?.verifiedCategoryTotals]
  );

  // 图表下钻：构造漏洞详情页查询参数
  const goVulns = useCallback((params: Record<string, string> = {}) => {
    const qs = new URLSearchParams(params).toString();
    navigate('/vulnerabilities' + (qs ? `?${qs}` : ''));
  }, [navigate]);

  const pieOption = useMemo(() => ({
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    series: [
      {
        type: 'pie',
        radius: '72%',
        center: ['50%', '50%'],
        avoidLabelOverlap: false,
        itemStyle: { borderColor: '#fff', borderWidth: 2 },
        label: { show: false },
        data: SEVERITY_ORDER.map((s) => ({
          value: sev[s],
          name: SEVERITY_LABEL[s],
          itemStyle: { color: SEV_HEX[s] },
        })),
      },
    ],
  }), [sev]);

  const barOption = useMemo(() => ({
    grid: { left: 50, right: 20, top: 20, bottom: 30 },
    tooltip: { trigger: 'axis' },
    xAxis: {
      type: 'category',
      data: BAR_SEV.map((s) => SEVERITY_LABEL[s]),
      axisLine: { lineStyle: { color: '#e6dfd8' } },
      axisLabel: { color: '#6c6a64' },
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
      splitLine: { lineStyle: { color: '#ebe6df' } },
      axisLabel: { color: '#6c6a64' },
    },
    series: [
      {
        type: 'bar',
        barWidth: '46%',
        label: {
          show: true,
          position: 'top',
          color: '#3a3833',
          fontWeight: 600,
          fontSize: 13,
        },
        data: BAR_SEV.map((s) => ({
          value: verifiedSev[s],
          itemStyle: { color: SEV_HEX[s], borderRadius: [6, 6, 0, 0] },
        })),
      },
    ],
  }), [verifiedSev]);

  const auditTypeOption = useMemo(
    () => typeBarOption(auditCats, '#cc785c'),
    [auditCats]
  );
  const verifiedTypeOption = useMemo(
    () => typeBarOption(verifiedCats, '#5db8a6'),
    [verifiedCats]
  );
  const auditTypeStyle = useMemo(
    () => ({ height: typeChartHeight(auditCats.length) }),
    [auditCats.length]
  );
  const verifiedTypeStyle = useMemo(
    () => ({ height: typeChartHeight(verifiedCats.length) }),
    [verifiedCats.length]
  );
  const pieEvents = useMemo(
    () => ({
      click: (params: any) => {
        const severity = LABEL_TO_SEV[params?.name];
        goVulns(severity ? { severity } : {});
      },
    }),
    [goVulns]
  );
  const verifiedEvents = useMemo(
    () => ({
      click: (params: any) => {
        const severity = LABEL_TO_SEV[params?.name];
        goVulns(severity ? { verified: '1', severity } : { verified: '1' });
      },
    }),
    [goVulns]
  );
  const auditTypeEvents = useMemo(
    () => ({
      click: (params: any) => params?.name && goVulns({ category: params.name }),
    }),
    [goVulns]
  );
  const verifiedTypeEvents = useMemo(
    () => ({
      click: (params: any) =>
        params?.name && goVulns({ verified: '1', category: params.name }),
    }),
    [goVulns]
  );

  return (
    <div className="dashboard">
      <div className="page-head dash-head">
        <div>
          <h1>数据大屏</h1>
          <p>实时掌握全部审计项目与漏洞态势</p>
        </div>
        <div className="dash-head-meta">
          <div className="dash-clock">{new Date().toLocaleDateString('zh-CN')}</div>
        </div>
      </div>

      {loadError && (
        <div className="card" role="alert">
          <strong>大屏数据暂时不可用</strong>
          <span className="muted"> · {loadError}</span>{' '}
          <button className="btn btn-secondary btn-sm" onClick={load}>
            重试
          </button>
        </div>
      )}

      <div className="stat-row">
        <StatCard
          label="项目总数"
          value={data?.totalProjects || 0}
          accent="ink"
          onClick={() => navigate('/projects')}
        />
        <StatCard
          label="审计进行中"
          value={data?.running || 0}
          accent="teal"
          live
          onClick={() => navigate('/projects?status=active')}
        />
        <StatCard
          label="漏洞总数"
          value={data?.totalVulns || 0}
          accent="primary"
          onClick={() => navigate('/vulnerabilities')}
        />
        <StatCard
          label="已验证漏洞"
          value={data?.verifiedVulns || 0}
          accent="critical"
          onClick={() => goVulns({ verified: '1' })}
        />
        <StatCard
          label="前台 RCE 漏洞"
          value={data?.frontendRceVulns || 0}
          accent="high"
          onClick={() => goVulns({ frontend_rce: '1' })}
        />
        <StatCard
          label="已完成项目"
          value={data?.allDoneProjects ?? 0}
          accent="success"
          // 大屏「已完成」= 全部远程验证完成（含历史/不含历史）；列表细分见 verify_done / verify_done_history。
          onClick={() => navigate('/projects?status=remote_done')}
        />
      </div>

      <div className="dash-grid">
        <div
          className="card chart-card clickable"
          onClick={() => goVulns()}
          role="button"
          title="点击查看全部漏洞"
        >
          <div className="chart-head">
            <h3>漏洞危害分布</h3>
            <span className="chart-link">查看详情 →</span>
          </div>
          <div className="pie-wrap">
            <ReactECharts
              option={pieOption}
              style={PIE_CHART_STYLE}
              lazyUpdate
              onEvents={pieEvents}
            />
            <div className="pie-legend">
              {SEVERITY_ORDER.map((s) => (
                <div
                  key={s}
                  className="legend-item legend-clickable"
                  onClick={(e) => {
                    e.stopPropagation();
                    goVulns({ severity: s });
                  }}
                >
                  <span className="legend-dot" style={{ background: SEV_HEX[s] }} />
                  <span>{SEVERITY_LABEL[s]}</span>
                  <strong>{sev[s]}</strong>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div
          className="card chart-card clickable"
          onClick={() => goVulns({ verified: '1' })}
          role="button"
          title="点击查看远程验证漏洞"
        >
          <div className="chart-head">
            <h3>已远程靶机验证真实漏洞分布</h3>
            <span className="chart-link">查看详情 →</span>
          </div>
          {(data?.verifiedVulns ?? 0) > 0 ? (
            <ReactECharts
              option={barOption}
              style={VERIFIED_CHART_STYLE}
              lazyUpdate
              onEvents={verifiedEvents}
            />
          ) : (
            <div className="empty-block" style={{ height: 280, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              暂无远程靶机验证成功的漏洞
            </div>
          )}
        </div>
      </div>

      <div className="dash-grid">
        <div
          className="card chart-card clickable"
          onClick={() => goVulns()}
          role="button"
          title="点击查看全部漏洞"
        >
          <div className="chart-head">
            <h3>代码审计漏洞类型分布</h3>
            <span className="chart-link">查看详情 →</span>
          </div>
          <p className="chart-sub">来源：全部代码审计漏洞（前 8 类）</p>
          {auditCats.length > 0 ? (
            <ReactECharts
              option={auditTypeOption}
              style={auditTypeStyle}
              lazyUpdate
              onEvents={auditTypeEvents}
            />
          ) : (
            <div className="empty-block" style={{ height: 180, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              暂无审计漏洞数据
            </div>
          )}
        </div>

        <div
          className="card chart-card clickable"
          onClick={() => goVulns({ verified: '1' })}
          role="button"
          title="点击查看远程验证漏洞"
        >
          <div className="chart-head">
            <h3>远程靶机验证漏洞类型分布</h3>
            <span className="chart-link">查看详情 →</span>
          </div>
          <p className="chart-sub">来源：远程靶机验证成功的漏洞（前 8 类）</p>
          {verifiedCats.length > 0 ? (
            <ReactECharts
              option={verifiedTypeOption}
              style={verifiedTypeStyle}
              lazyUpdate
              onEvents={verifiedTypeEvents}
            />
          ) : (
            <div className="empty-block" style={{ height: 180, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              暂无验证成功的漏洞
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  accent,
  live,
  onClick,
}: {
  label: string;
  value: number;
  accent: string;
  live?: boolean;
  onClick?: () => void;
}) {
  return (
    <div
      className={`stat-card accent-${accent}${onClick ? ' clickable' : ''}`}
      onClick={onClick}
      role={onClick ? 'button' : undefined}
    >
      <div className="stat-label">
        {label}
        {live && <span className="live-dot" />}
      </div>
      <Counter value={value} className="stat-value" />
    </div>
  );
}
