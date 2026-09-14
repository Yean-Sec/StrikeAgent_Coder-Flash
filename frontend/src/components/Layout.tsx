import { memo, Suspense, useEffect, useState } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { api } from '../lib/api';
import NavIcon from './NavIcon';
import RouteErrorBoundary from './RouteErrorBoundary';
import './Layout.css';

const NAV = [
  { to: '/dashboard', label: '数据大屏', icon: 'dashboard' },
  { to: '/projects', label: '审计列表', icon: 'projects' },
  { to: '/monitors', label: '监控模式', icon: 'monitors' },
  { to: '/recycle', label: '回收站', icon: 'recycle' },
  { to: '/settings', label: '设置', icon: 'settings' },
];

type PiEngineState = {
  loading: boolean;
  ok: boolean;
  version?: string;
  error?: string;
};

type FootStatus = PiEngineState & { kind: 'checking' | 'ok' | 'pi_down' | 'backend_busy' | 'backend_down' };

const PiHealthStatus = memo(function PiHealthStatus() {
  const [state, setState] = useState<FootStatus>({
    loading: true,
    ok: false,
    kind: 'checking',
  });

  useEffect(() => {
    let alive = true;
    let failStreak = 0;

    const check = async () => {
      try {
        // 先探后端存活：短超时。失败再区分忙/断。
        try {
          await api.backendHealth();
        } catch {
          failStreak += 1;
          if (!alive) return;
          // 单次失败不立刻吓人：可能是事件循环短暂忙碌；连续两次才标红。
          if (failStreak >= 2) {
            setState({
              loading: false,
              ok: false,
              kind: 'backend_down',
              error: '无法连接后端',
            });
          } else {
            setState((prev) => ({
              ...prev,
              loading: false,
              kind: prev.ok ? 'ok' : 'backend_busy',
              error: prev.ok ? prev.error : '后端忙碌，稍后自动重试',
            }));
          }
          return;
        }

        const result = await api.piHealth();
        if (!alive) return;
        failStreak = 0;
        setState({
          loading: false,
          ok: result.ok,
          version: result.version,
          error: result.error,
          kind: result.ok ? 'ok' : 'pi_down',
        });
      } catch {
        if (!alive) return;
        failStreak += 1;
        // Pi 健康接口超时但 /health 已通：后端在，只是忙或 Pi 探测慢。
        setState((prev) => ({
          loading: false,
          ok: prev.ok,
          version: prev.version,
          kind: failStreak >= 2 ? 'backend_busy' : prev.kind === 'checking' ? 'backend_busy' : prev.kind,
          error: '后端繁忙，状态稍后刷新',
        }));
      }
    };

    void check();
    const timer = window.setInterval(() => void check(), 15_000);

    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, []);

  const status =
    state.kind === 'checking'
      ? 'checking'
      : state.kind === 'ok'
        ? 'ok'
        : state.kind === 'backend_busy'
          ? 'busy'
          : 'down';
  const label =
    state.kind === 'checking'
      ? '检测中…'
      : state.kind === 'ok'
        ? 'Pi 引擎正常'
        : state.kind === 'pi_down'
          ? 'Pi 不可用'
          : state.kind === 'backend_busy'
            ? '后端繁忙'
            : '无法连接后端';
  const detail =
    state.kind === 'checking'
      ? '本地 Pi 引擎'
      : state.kind === 'ok'
        ? state.version || '本地 Pi 引擎'
        : state.error || '请稍后重试';

  return (
    <div
      className={`sidebar-foot pi-${status}`}
      title={`${label}${detail ? ` · ${detail}` : ''}`}
    >
      <span className="dot" />
      <div className="pi-info">
        <span className="pi-label">{label}</span>
        <span className="pi-sub ellipsis">{detail}</span>
      </div>
    </div>
  );
});

export default function Layout() {
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem('sidebar_collapsed') === '1'
  );
  const navigate = useNavigate();
  const location = useLocation();

  const toggle = () => {
    setCollapsed((c) => {
      localStorage.setItem('sidebar_collapsed', c ? '0' : '1');
      return !c;
    });
  };

  return (
    <div className={'layout' + (collapsed ? ' collapsed' : '')}>
      <aside className="sidebar">
        <button
          className="collapse-btn"
          onClick={toggle}
          title={collapsed ? '展开侧边栏' : '收起侧边栏'}
        >
          {collapsed ? '»' : '«'}
        </button>

        <div className="logo" title="StrikeAgent_Coder-Flash · 代码审计">
          <img
            className="logo-mark"
            src="/brand-mark.png"
            alt=""
            width={32}
            height={32}
            draggable={false}
          />
          <div className="logo-text">
            <strong className="logo-name">
              <span>StrikeAgent_</span>
              <span>Coder-Flash</span>
            </strong>
            <span className="logo-tag">代码审计</span>
          </div>
        </div>

        <button
          className="new-audit-btn"
          onClick={() => navigate('/projects/new')}
          title="新建审计"
        >
          <span className="na-plus">＋</span>
          <span className="na-text">新建审计</span>
        </button>

        <nav className="nav">
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              title={n.label}
              className={({ isActive }) => 'nav-link' + (isActive ? ' active' : '')}
            >
              <span className="nav-icon"><NavIcon name={n.icon} /></span>
              <span className="nav-label">{n.label}</span>
            </NavLink>
          ))}
        </nav>

        <PiHealthStatus />
      </aside>
      <main className="content">
        <RouteErrorBoundary key={location.pathname}>
          <Suspense fallback={<div className="card">页面加载中…</div>}>
            <Outlet />
          </Suspense>
        </RouteErrorBoundary>
      </main>
    </div>
  );
}
