import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '../lib/api';
import { wsClient } from '../lib/ws';
import type { Monitor } from '../lib/types';
import { fmtRelative } from '../lib/format';
import './Monitors.css';

export default function Monitors() {
  const [monitors, setMonitors] = useState<Monitor[]>([]);
  const [repoUrl, setRepoUrl] = useState('');
  const [prefix, setPrefix] = useState('');
  const [interval, setIntervalMin] = useState('5');
  const [busy, setBusy] = useState(false);
  const [toast, setToast] = useState('');
  const reloadTimer = useRef<number | null>(null);
  const toastTimer = useRef<number | null>(null);

  const load = useCallback(
    () => api.listMonitors().then(setMonitors).catch(() => {}),
    []
  );

  useEffect(() => {
    load();
    const unsub = wsClient.subscribe((msg) => {
      if (
        msg.type === 'monitor_triggered' ||
        msg.type === 'monitor_checked'
      ) {
        if (reloadTimer.current) clearTimeout(reloadTimer.current);
        reloadTimer.current = window.setTimeout(() => {
          reloadTimer.current = null;
          load();
        }, 250);
        if (msg.type === 'monitor_triggered') {
          setToast(`检测到新版本 ${msg.tag}，已自动发起审计`);
          if (toastTimer.current) clearTimeout(toastTimer.current);
          toastTimer.current = window.setTimeout(() => {
            toastTimer.current = null;
            setToast('');
          }, 4000);
        }
      }
    }, { scope: 'monitors' });
    return () => {
      unsub();
      if (reloadTimer.current) clearTimeout(reloadTimer.current);
      if (toastTimer.current) clearTimeout(toastTimer.current);
    };
  }, [load]);

  const add = async () => {
    if (!repoUrl.trim()) return;
    setBusy(true);
    try {
      await api.createMonitor({
        repo_url: repoUrl.trim(),
        project_prefix: prefix.trim(),
        interval_min: parseInt(interval, 10) || 5,
      });
      setRepoUrl('');
      setPrefix('');
      load();
    } finally {
      setBusy(false);
    }
  };

  const toggle = async (m: Monitor) => {
    await api.updateMonitor(m.id, { enabled: m.enabled ? 0 : 1 });
    load();
  };

  const checkNow = async (m: Monitor) => {
    await api.checkMonitor(m.id);
    load();
  };

  const remove = async (m: Monitor) => {
    if (!confirm('确认删除该监控？')) return;
    await api.deleteMonitor(m.id);
    load();
  };

  return (
    <div className="monitors-page">
      <div className="page-head">
        <h1>监控模式</h1>
        <p>持续监控 GitHub 仓库的 Releases，发布新版本即自动发起审计</p>
      </div>

      {toast && <div className="monitor-toast">{toast}</div>}

      <div className="card monitor-form">
        <div className="form-grid">
          <div className="form-field grow">
            <label>GitHub 仓库地址</label>
            <input
              className="input"
              placeholder="https://github.com/owner/repo"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
            />
          </div>
          <div className="form-field">
            <label>项目名前缀（可选）</label>
            <input
              className="input"
              placeholder="默认使用仓库名"
              value={prefix}
              onChange={(e) => setPrefix(e.target.value)}
            />
          </div>
          <div className="form-field small">
            <label>轮询间隔（分钟）</label>
            <input
              className="input"
              type="number"
              min={1}
              value={interval}
              onChange={(e) => setIntervalMin(e.target.value)}
            />
          </div>
          <button className="btn btn-primary add-btn" disabled={busy} onClick={add}>
            添加监控
          </button>
        </div>
      </div>

      <div className="monitor-list">
        {monitors.map((m) => (
          <div key={m.id} className={'card monitor-item' + (m.enabled ? '' : ' off')}>
            <div className="monitor-main">
              <div className="monitor-repo">
                <span className={'mon-led' + (m.enabled ? ' on' : '')} />
                <strong>{m.repo_url}</strong>
              </div>
              <div className="monitor-meta">
                <span>当前基线版本：{m.last_release_tag || '尚未检测'}</span>
                <span>间隔 {m.interval_min} 分钟</span>
                <span>最近检查：{fmtRelative(m.last_checked)}</span>
                <span>最近触发：{fmtRelative(m.last_triggered)}</span>
              </div>
            </div>
            <div className="monitor-actions">
              <button className="btn btn-ghost" onClick={() => checkNow(m)}>
                立即检查
              </button>
              <button className="btn btn-ghost" onClick={() => toggle(m)}>
                {m.enabled ? '停用' : '启用'}
              </button>
              <button className="btn btn-ghost danger-text" onClick={() => remove(m)}>
                删除
              </button>
            </div>
          </div>
        ))}
        {monitors.length === 0 && (
          <div className="empty-block">还没有监控任务，添加一个 GitHub 仓库开始监控</div>
        )}
      </div>
    </div>
  );
}
