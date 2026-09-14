import { memo, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useVirtualizer } from '@tanstack/react-virtual';
import { api } from '../lib/api';
import { wsClient } from '../lib/ws';
import type { Project, WebClassifyCandidate, WebClassifyStatus } from '../lib/types';
import { PhaseBadge } from '../components/Badges';
import NextStepModal from '../components/NextStepModal';
import { useToast } from '../components/Toast';
import { fmtDateMinute, fmtDuration, totalVulns } from '../lib/format';
import './Projects.css';

type StatusFilter =
  | 'all'
  | 'active'
  | 'verify_running'
  | 'verify_queued'
  | 'audit_queued'
  | 'audit_running'
  | 'all_done'
  | 'audit_done'
  | 'remote_done'
  | 'verify_done'
  | 'verify_done_history'
  | 'paused'
  | 'audit_paused'
  | 'verify_paused'
  | 'failed';
type GroupBy = 'none' | 'date' | 'system';
type ProjectMetaPatch = {
  project_name?: string;
  source_version?: string | null;
  system_name?: string | null;
};
type ProjectListEntry =
  | { kind: 'group'; key: string; label: string; count: number }
  | { kind: 'project'; key: string; project: Project };

const ACTIVE_FILTER_KEYS: StatusFilter[] = [
  'active',
  'verify_running',
  'verify_queued',
  'audit_queued',
  'audit_running',
];

const ACTIVE_MENU: { key: StatusFilter; label: string }[] = [
  { key: 'active', label: '全部进行中' },
  { key: 'verify_running', label: '靶机验证中' },
  { key: 'verify_queued', label: '验证排队中' },
  { key: 'audit_queued', label: '审计排队中' },
  { key: 'audit_running', label: '代码审计中' },
];

const DONE_FILTER_KEYS: StatusFilter[] = [
  'all_done',
  'audit_done',
  'remote_done',
  'verify_done',
  'verify_done_history',
];

const DONE_MENU: { key: StatusFilter; label: string }[] = [
  { key: 'all_done', label: '全部完成' },
  { key: 'audit_done', label: '代码审计完成' },
  { key: 'verify_done', label: '代码审计+远程验证' },
];

const PAUSED_FILTER_KEYS: StatusFilter[] = ['paused', 'audit_paused', 'verify_paused'];

const PAUSED_MENU: { key: StatusFilter; label: string }[] = [
  { key: 'paused', label: '全部已暂停' },
  { key: 'audit_paused', label: '代码审计未完成暂停' },
  { key: 'verify_paused', label: '远程验证未完成暂停' },
];

const GROUP_OPTIONS: { key: GroupBy; label: string }[] = [
  { key: 'none', label: '不分组' },
  { key: 'date', label: '按审计时间' },
  { key: 'system', label: '按项目' },
];

/** 项目的"审计时间"参考点：完成 > 开始 > 创建。 */
function projTime(p: Project): number {
  return p.finished_at || p.started_at || p.created_at;
}

/** 按审计日期归桶（今天/昨天/具体日期），返回 {key 排序用, label 展示}。 */
function dateBucket(ts: number): { key: string; label: string } {
  const d = new Date(ts);
  const ymd = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(
    d.getDate()
  ).padStart(2, '0')}`;
  const today = new Date();
  const startOf = (x: Date) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const dayMs = 86400000;
  const diffDays = Math.round((startOf(today) - startOf(d)) / dayMs);
  let label = ymd;
  if (diffDays === 0) label = `今天 ${ymd}`;
  else if (diffDays === 1) label = `昨天 ${ymd}`;
  return { key: ymd, label };
}

/** 项目归属的"系统"（同系统多版本聚一组）：优先 system_name，回退去版本号的项目名。 */
function systemBucket(p: Project): string {
  const sys = (p.system_name || '').trim();
  if (sys) return sys;
  const base = p.project_name
    .replace(/[-_ ]v?\d+(\.\d+)*([.-][0-9A-Za-z]+)*$/i, '')
    .trim();
  return base || p.project_name;
}

const FILTERS: { key: StatusFilter; label: string }[] = [
  { key: 'all', label: '全部' },
  { key: 'failed', label: '失败' },
];

const ALL_FILTER_KEYS: StatusFilter[] = [
  ...FILTERS.map((f) => f.key),
  ...ACTIVE_MENU.map((f) => f.key),
  ...DONE_MENU.map((f) => f.key),
  // 大屏「已完成项目」入口：远程验证完成并集（含/不含历史），不单独出现在下拉菜单。
  'remote_done',
  ...PAUSED_MENU.map((f) => f.key),
];

function isActiveGroupFilter(f: StatusFilter): boolean {
  return ACTIVE_FILTER_KEYS.includes(f);
}

function isDoneGroupFilter(f: StatusFilter): boolean {
  return DONE_FILTER_KEYS.includes(f);
}

function isPausedGroupFilter(f: StatusFilter): boolean {
  return PAUSED_FILTER_KEYS.includes(f);
}

/** 与后端 PROJECT_STATUS_SQL 保持同一口径，用于判断 WS 补丁是否改变当前筛选成员。 */
function matchesStatusFilter(p: Project, filter: StatusFilter): boolean {
  switch (filter) {
    case 'all':
      return true;
    case 'active':
      return (
        p.status === 'running' ||
        p.status === 'queued' ||
        p.verify_status === 'running' ||
        p.verify_status === 'queued'
      );
    case 'verify_running':
      return p.verify_status === 'running';
    case 'verify_queued':
      return p.status === 'completed' && p.verify_status === 'queued';
    case 'audit_queued':
      return p.status === 'queued';
    case 'audit_running':
      return p.status === 'running';
    case 'all_done':
      return (
        (p.status === 'completed' && p.verify_status === 'none') ||
        p.verify_status === 'completed'
      );
    case 'audit_done':
      return p.status === 'completed' && p.verify_status === 'none';
    case 'remote_done':
      return p.verify_status === 'completed';
    case 'verify_done':
      // 与后端一致：远程验证完成，且未同时满足「开关开启 + 真实历史产物」
      return p.verify_status === 'completed' && (p.has_history_verify ?? 0) === 0;
    case 'verify_done_history':
      return p.verify_status === 'completed' && (p.has_history_verify ?? 0) !== 0;
    case 'paused':
      return p.status === 'paused' || p.verify_status === 'paused';
    case 'audit_paused':
      return p.status === 'paused';
    case 'verify_paused':
      return p.verify_status === 'paused';
    case 'failed':
      return p.status === 'failed' || p.verify_status === 'failed';
  }
}

/** 是否可继续（被暂停或失败的审计/验证）。 */
function canContinue(p: Project): boolean {
  return (
    p.status === 'paused' ||
    p.status === 'failed' ||
    p.verify_status === 'paused' ||
    p.verify_status === 'failed'
  );
}

function canPause(p: Project): boolean {
  return (
    p.status === 'running' ||
    p.status === 'queued' ||
    p.verify_status === 'running' ||
    p.verify_status === 'queued'
  );
}

/**
 * 返回恒定引用的事件回调，同时始终调用最新实现。
 * 这样父页面状态变化不会让 memo 行仅因函数 identity 改变而重渲染。
 */
function useEventCallback<T extends (...args: any[]) => any>(callback: T): T {
  const callbackRef = useRef(callback);
  callbackRef.current = callback;
  return useCallback(
    ((...args: Parameters<T>) => callbackRef.current(...args)) as T,
    []
  );
}

/**
 * 该项目是否处于「代码审计已完成、但作为仅代码审计任务尚未做靶机验证」的状态——
 * 点「继续」时不应默默续跑，而应弹出下一步选择框（取消 / 进入靶机验证）。
 * 仅当项目显式选择了「仅代码审计」（opt_auto_verify===0）时成立；opt_auto_verify 为 null
 * 表示沿用全局默认（全流程），续跑会自动进入验证，不在此列。
 */
function needsNextStep(p: Project): boolean {
  return (
    p.status === 'completed' &&
    p.verify_status === 'none' &&
    p.opt_auto_verify === 0
  );
}

export default function Projects() {
  const [projects, setProjects] = useState<Project[]>([]);
  // 输入框自行维护展示值；这里只有 250ms 静默期后的实际查询值。
  const [querySearch, setQuerySearch] = useState('');
  const [searchParams] = useSearchParams();
  const initialFilter = ALL_FILTER_KEYS.includes(searchParams.get('status') as StatusFilter)
    ? (searchParams.get('status') as StatusFilter)
    : 'all';
  const [statusFilter, setStatusFilter] = useState<StatusFilter>(initialFilter);
  const [activeMenuOpen, setActiveMenuOpen] = useState(false);
  const [doneMenuOpen, setDoneMenuOpen] = useState(false);
  const [pausedMenuOpen, setPausedMenuOpen] = useState(false);
  const activeMenuRef = useRef<HTMLDivElement>(null);
  const doneMenuRef = useRef<HTMLDivElement>(null);
  const pausedMenuRef = useRef<HTMLDivElement>(null);
  const [groupBy, setGroupBy] = useState<GroupBy>('none');
  const [batchTarget, setBatchTarget] = useState<Project | null>(null);
  // 「继续」下一步选择框目标：审计完成但仅代码审计、尚未验证的项目点继续时弹出。
  const [nextStepTarget, setNextStepTarget] = useState<Project | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [delProgress, setDelProgress] = useState<{
    total: number;
    done: number;
    current: string;
  } | null>(null);
  // 批量 Web 端判定 + 清理
  const [classifyOpen, setClassifyOpen] = useState(false);
  const [classifyStatus, setClassifyStatus] = useState<WebClassifyStatus | null>(null);
  const [classifyPicked, setClassifyPicked] = useState<Set<string>>(new Set());
  const classifyTimerRef = useRef<number | null>(null);
  const navigate = useNavigate();
  const toast = useToast();
  // 平铺与分组列表均分页：一次显示 10/30/50 个
  const [pageSize, setPageSize] = useState(30);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [filterCounts, setFilterCounts] = useState<Record<string, number>>({});
  const [listLoading, setListLoading] = useState(true);
  const [reconcilingContainers, setReconcilingContainers] = useState(false);
  const projectsRef = useRef(projects);
  projectsRef.current = projects;
  const searchRef = useRef(querySearch);
  searchRef.current = querySearch;
  const reloadTimerRef = useRef<number | null>(null);
  const reloadIncludeCountsRef = useRef(false);
  const loadSeqRef = useRef(0);
  const queryRef = useRef({ statusFilter, page, pageSize, groupBy });
  queryRef.current = { statusFilter, page, pageSize, groupBy };

  const load = (q = searchRef.current, includeCounts = true) => {
    const seq = ++loadSeqRef.current;
    const query = queryRef.current;
    setListLoading(true);
    return api
      .listProjects({
        search: q,
        status: query.statusFilter,
        page: query.page,
        pageSize: query.pageSize,
        groupBy: query.groupBy,
        includeCounts: includeCounts ? 1 : 0,
      })
      .then((result) => {
        // 搜索与 WS 刷新可能并行，只接受最后发起的请求，避免旧响应覆盖新结果。
        if (seq !== loadSeqRef.current) return;
        projectsRef.current = result.items;
        setProjects(result.items);
        setTotal(result.total);
        if (result.counts) setFilterCounts(result.counts);
        if (result.page !== queryRef.current.page) setPage(result.page);
      })
      .catch(() => {
        if (seq === loadSeqRef.current) toast('项目列表加载失败，请确认后端已启动', 'error');
      })
      .finally(() => {
        if (seq === loadSeqRef.current) setListLoading(false);
      });
  };

  const onSearchQueryChange = useCallback((value: string) => {
    setPage(1);
    setSelected(new Set());
    setQuerySearch(value);
  }, []);

  useEffect(() => {
    const s = searchParams.get('status');
    if (s && ALL_FILTER_KEYS.includes(s as StatusFilter)) {
      setStatusFilter(s as StatusFilter);
    }
  }, [searchParams]);

  useEffect(() => {
    if (!activeMenuOpen) return;
    const onDoc = (e: MouseEvent) => {
      if (activeMenuRef.current && !activeMenuRef.current.contains(e.target as Node)) {
        setActiveMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [activeMenuOpen]);

  useEffect(() => {
    if (!doneMenuOpen) return;
    const onDoc = (e: MouseEvent) => {
      if (doneMenuRef.current && !doneMenuRef.current.contains(e.target as Node)) {
        setDoneMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [doneMenuOpen]);

  useEffect(() => {
    if (!pausedMenuOpen) return;
    const onDoc = (e: MouseEvent) => {
      if (pausedMenuRef.current && !pausedMenuRef.current.contains(e.target as Node)) {
        setPausedMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [pausedMenuOpen]);

  // 卸载时停止批量判定轮询
  useEffect(() => {
    return () => {
      if (classifyTimerRef.current) clearInterval(classifyTimerRef.current);
    };
  }, []);

  const applyStatusFilter = (key: StatusFilter) => {
    setStatusFilter(key);
    setActiveMenuOpen(false);
    setDoneMenuOpen(false);
    setPausedMenuOpen(false);
    navigate(key === 'all' ? '/projects' : `/projects?status=${key}`, { replace: true });
  };

  useEffect(() => {
    // 可完整表达的单项目消息直接补丁；只有成员变化、终态或缺少派生字段时才同步列表。
    const unsub = wsClient.subscribe((msg) => {
      if (msg.type !== 'project_status') return;
      const scheduleReload = (includeCounts: boolean) => {
        reloadIncludeCountsRef.current ||= includeCounts;
        if (reloadTimerRef.current != null) return;
        reloadTimerRef.current = window.setTimeout(() => {
          reloadTimerRef.current = null;
          const needsCounts = reloadIncludeCountsRef.current;
          reloadIncludeCountsRef.current = false;
          load(searchRef.current, needsCounts);
        }, 1200);
      };

      let foundProject = false;
      let membershipChanged = false;
      let missingDerivedFields = false;
      let patchSize = 0;
      if (msg.projectId) {
        const patchKeys = [
          'status',
          'verify_status',
          'env_status',
          'has_web',
          'has_registration',
          'reg_default_open',
          'target_url',
          'error_message',
          'verify_error',
          'started_at',
          'finished_at',
          'verify_started_at',
          'verify_finished_at',
          'audit_duration_ms',
          'verify_duration_ms',
        ] as const;
        const patch: Partial<Project> = {};
        for (const key of patchKeys) {
          if (msg[key] !== undefined) (patch as Record<string, unknown>)[key] = msg[key];
        }
        patchSize = Object.keys(patch).length;
        const current = projectsRef.current.find((p) => p.id === msg.projectId);
        if (current && patchSize > 0) {
          foundProject = true;
          const nextProject = { ...current, ...patch };
          const currentFilter = queryRef.current.statusFilter;
          membershipChanged =
            matchesStatusFilter(current, currentFilter) !==
            matchesStatusFilter(nextProject, currentFilter);
          // 后端在 running -> 非 running 时累计耗时，但旧消息未必携带累计值。
          missingDerivedFields =
            (current.status === 'running' &&
              msg.status !== undefined &&
              msg.status !== 'running' &&
              msg.audit_duration_ms === undefined) ||
            (current.verify_status === 'running' &&
              msg.verify_status !== undefined &&
              msg.verify_status !== 'running' &&
              msg.verify_duration_ms === undefined);

          const refList = projectsRef.current.map((p) =>
            p.id === msg.projectId ? nextProject : p
          );
          projectsRef.current = refList;
          setProjects((list) =>
            list.map((p) => (p.id === msg.projectId ? { ...p, ...patch } : p))
          );

          if (msg.status !== undefined || msg.verify_status !== undefined) {
            setFilterCounts((counts) => {
              let changed = false;
              const nextCounts = { ...counts };
              for (const key of ALL_FILTER_KEYS) {
                const before = matchesStatusFilter(current, key);
                const after = matchesStatusFilter(nextProject, key);
                if (before === after) continue;
                nextCounts[key] = Math.max(0, (nextCounts[key] ?? 0) + (after ? 1 : -1));
                changed = true;
              }
              return changed ? nextCounts : counts;
            });
          }
        }
      }

      const terminal =
        ['completed', 'failed'].includes(msg.status) ||
        ['completed', 'failed'].includes(msg.verify_status);
      const phaseChanged = msg.status !== undefined || msg.verify_status !== undefined;
      // 验证进度只影响详情页，不应触发 657+ 项目的整表传输与解析。
      if (msg.exploit_progress && !terminal) return;
      if (terminal || patchSize === 0) {
        scheduleReload(patchSize === 0);
        return;
      }
      if (
        phaseChanged &&
        (!foundProject || membershipChanged || missingDerivedFields)
      ) {
        scheduleReload(false);
      }
    }, { scope: 'projects' });
    return () => {
      unsub();
      if (reloadTimerRef.current != null) clearTimeout(reloadTimerRef.current);
    };
  }, []);

  useEffect(() => {
    void load(querySearch);
  }, [querySearch, statusFilter, page, pageSize, groupBy]);

  // 服务端已完成搜索、状态过滤和分页，当前数组就是本页可见项目。
  const filtered = projects;

  const activeButtonLabel =
    statusFilter === 'active'
      ? '进行中'
      : ACTIVE_MENU.find((m) => m.key === statusFilter)?.label ?? '进行中';

  const doneButtonLabel =
    statusFilter === 'all_done'
      ? '全部完成'
      : statusFilter === 'remote_done'
        ? '远程验证完成'
        : DONE_MENU.find((m) => m.key === statusFilter)?.label ?? '全部完成';

  // 大屏入口 status=remote_done 不在下拉里：主按钮标签/计数/点击必须跟当前子筛选一致，
  // 否则会显示 all_done 的 265、一点击又跳去「全部完成」，看起来像没进已完成。
  const doneMainFilter: StatusFilter = isDoneGroupFilter(statusFilter)
    ? statusFilter
    : 'all_done';
  const doneButtonCount = filterCounts[doneMainFilter] ?? 0;

  const pausedButtonLabel =
    statusFilter === 'paused'
      ? '已暂停'
      : PAUSED_MENU.find((m) => m.key === statusFilter)?.label ?? '已暂停';

  // 分页切片始终生效；分组只整理当前页，防止一次创建数百个表格与菜单。
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const curPage = Math.min(page, totalPages);
  const paged = projects;

  // 筛选/搜索/分组/每页数量变化时回到第 1 页
  useEffect(() => {
    setPage(1);
    setSelected(new Set());
  }, [statusFilter, pageSize, groupBy]);

  useEffect(() => {
    setSelected(new Set());
  }, [page]);

  // 分组：按审计时间（日期桶，新→旧）或按项目（系统名，组内新→旧）
  const groups = useMemo(() => {
    if (groupBy === 'none') return null;
    const map = new Map<string, { label: string; sortKey: string | number; items: Project[] }>();
    for (const p of paged) {
      let key: string;
      let label: string;
      let sortKey: string | number;
      if (groupBy === 'date') {
        const b = dateBucket(projTime(p));
        key = b.key;
        label = b.label;
        sortKey = b.key; // YYYY-MM-DD 字典序 == 时间序
      } else {
        key = systemBucket(p).toLowerCase();
        label = systemBucket(p);
        sortKey = label.toLowerCase();
      }
      if (!map.has(key)) map.set(key, { label, sortKey, items: [] });
      map.get(key)!.items.push(p);
    }
    const arr = [...map.values()];
    if (groupBy === 'date') {
      arr.sort((a, b) => String(b.sortKey).localeCompare(String(a.sortKey))); // 日期新→旧
      for (const g of arr) g.items.sort((a, b) => projTime(b) - projTime(a));
    } else {
      arr.sort((a, b) => b.items.length - a.items.length || String(a.sortKey).localeCompare(String(b.sortKey)));
      for (const g of arr) g.items.sort((a, b) => projTime(b) - projTime(a));
    }
    return arr;
  }, [paged, groupBy]);

  // 平铺与分组共用同一个虚拟序列；分组标题也是可虚拟化条目。
  const listEntries = useMemo<ProjectListEntry[]>(() => {
    if (groups === null) {
      return paged.map((project) => ({
        kind: 'project',
        key: `project:${project.id}`,
        project,
      }));
    }
    return groups.flatMap((group) => [
      {
        kind: 'group' as const,
        key: `group:${groupBy}:${String(group.sortKey)}`,
        label: group.label,
        count: group.items.length,
      },
      ...group.items.map((project) => ({
        kind: 'project' as const,
        key: `project:${project.id}`,
        project,
      })),
    ]);
  }, [groupBy, groups, paged]);

  const toggle = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };
  const allSelected = filtered.length > 0 && filtered.every((p) => selected.has(p.id));
  const toggleAll = () => {
    setSelected(allSelected ? new Set() : new Set(filtered.map((p) => p.id)));
  };

  const continuableSelected = filtered.filter(
    (p) => selected.has(p.id) && canContinue(p)
  ).length;

  const onPause = async (id: string) => {
    await api.pause(id);
    load();
  };
  const onResume = async (p: Project) => {
    // 审计已完成的「仅代码审计」项目：点继续不直接续跑，弹出下一步选择框。
    if (needsNextStep(p)) {
      setNextStepTarget(p);
      return;
    }
    try {
      await api.resume(p.id);
      toast('已继续任务', 'success');
      load();
    } catch (e: any) {
      toast('继续失败：' + (e?.response?.data?.error || e.message), 'error');
    }
  };
  // 下一步选择框：进入靶机验证（仅当前版本）。
  const onChooseNextStep = async () => {
    const p = nextStepTarget;
    if (!p) return;
    setNextStepTarget(null);
    try {
      await api.verify(p.id, { verify_history: false });
      toast('已发起靶机验证', 'success');
      load();
    } catch (e: any) {
      toast('发起验证失败：' + (e?.response?.data?.error || e.message), 'error');
    }
  };
  // 逐个删除，实时反馈进度。单个删除与批量删除共用。
  const runDelete = async (targets: Project[]) => {
    setDelProgress({
      total: targets.length,
      done: 0,
      current: targets.length === 1 ? targets[0].project_name : `批量删除 ${targets.length} 个项目…`,
    });
    let ok = 0;
    let failed = 0;
    try {
      if (targets.length === 1) {
        await api.remove(targets[0].id);
        ok = 1;
      } else {
        // 一次 bulk 请求，避免逐个串行 HTTP + 同步删盘把 UI 拖死
        const res = await api.bulkDelete(targets.map((p) => p.id));
        ok = Number(res?.count ?? 0);
        failed = Array.isArray(res?.failed) ? res.failed.length : Math.max(0, targets.length - ok);
      }
      setDelProgress({ total: targets.length, done: ok, current: '' });
      setSelected((s) => {
        const n = new Set(s);
        for (const p of targets) n.delete(p.id);
        return n;
      });
    } catch {
      failed = targets.length;
      ok = 0;
    }
    setDelProgress(null);
    if (failed === 0) toast(`已删除 ${ok} 个项目`, 'success');
    else toast(`删除完成：成功 ${ok} 个，失败 ${failed} 个`, failed === targets.length ? 'error' : 'info');
    load();
  };

  const onDelete = async (id: string) => {
    if (!confirm('确认删除该项目及其审计数据？')) return;
    const p = projects.find((x) => x.id === id);
    if (p) await runDelete([p]);
  };

  const bulkPause = async () => {
    const ids = [...selected];
    try {
      await api.bulkPause(ids);
      toast(`已暂停 ${ids.length} 个任务`, 'success');
    } catch (e: any) {
      toast('批量暂停失败：' + (e?.response?.data?.error || e.message), 'error');
    }
    load();
  };
  const bulkResume = async () => {
    const targets = filtered.filter((p) => selected.has(p.id) && canContinue(p));
    if (targets.length === 0) {
      toast('选中项目中没有可继续的任务（仅已暂停/失败可继续）', 'info');
      return;
    }
    try {
      const res = await api.bulkResume(targets.map((p) => p.id));
      if (res?.async) {
        toast(`正在为 ${res.accepted ?? targets.length} 个项目后台排队继续，请稍后刷新列表`, 'success');
      } else {
        toast(`已继续 ${res?.count ?? targets.length} 个任务`, 'success');
      }
    } catch (e: any) {
      toast('批量继续失败：' + (e?.response?.data?.error || e.message), 'error');
    }
    load();
  };
  const bulkDelete = async () => {
    if (!confirm(`确认删除选中的 ${selected.size} 个项目？`)) return;
    const targets = projects.filter((p) => selected.has(p.id));
    if (targets.length === 0) return;
    await runDelete(targets);
  };

  // —— 批量 Web 端语义判定 + 清理 ——
  const stopClassifyPoll = () => {
    if (classifyTimerRef.current) {
      clearInterval(classifyTimerRef.current);
      classifyTimerRef.current = null;
    }
  };
  const pollClassify = async () => {
    try {
      const s = await api.classifyWebStatus();
      setClassifyStatus(s);
      if (s.phase === 'awaiting_confirm' || s.phase === 'done') {
        // 判定结束：默认全选非 Web 候选，交由用户确认删除
        setClassifyPicked(new Set(s.nonWeb.map((c) => c.id)));
        stopClassifyPoll();
      } else if (s.phase === 'idle') {
        stopClassifyPoll();
      }
    } catch {
      /* 忽略单次轮询失败 */
    }
  };
  const openClassify = async () => {
    setClassifyOpen(true);
    // 若已有进行中/待确认的批处理，直接接管展示；否则展示 idle
    await pollClassify();
    if (!classifyTimerRef.current) {
      const s = await api.classifyWebStatus().catch(() => null);
      if (s && (s.phase === 'classifying' || s.phase === 'deleting')) {
        classifyTimerRef.current = window.setInterval(pollClassify, 2000);
      }
    }
  };
  const startClassify = async () => {
    if (
      !confirm(
        '将对全库所有项目用 LLM 逐个判定是否含 Web 端（未判定的首判、已判定的强制重判）。\n判定完成后会列出「无 Web 端」清单，由你勾选后再批量删除。\n未克隆的项目会先克隆并建图，属于长任务。\n确认开始？'
      )
    )
      return;
    try {
      const r = await api.classifyWebStart();
      if (!r.ok) {
        toast(r.error || '批处理已在进行中', 'error');
        return;
      }
      toast(`已启动批量判定，共 ${r.total ?? 0} 个项目`, 'success');
      await pollClassify();
      stopClassifyPoll();
      classifyTimerRef.current = window.setInterval(pollClassify, 2000);
    } catch (e: any) {
      toast('启动失败：' + (e?.response?.data?.error || e.message), 'error');
    }
  };
  const cancelClassify = async () => {
    await api.classifyWebCancel().catch(() => {});
    toast('已请求取消，正在停止…', 'success');
    await pollClassify();
  };
  const toggleClassifyPick = (id: string) => {
    setClassifyPicked((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };
  const confirmClassifyDelete = async () => {
    const ids = [...classifyPicked];
    if (ids.length === 0) return;
    if (!confirm(`确认删除这 ${ids.length} 个判定为「无 Web 端」的项目？删除记录会进入回收站。`)) return;
    try {
      const r = await api.classifyWebConfirmDelete(ids);
      toast(`已删除 ${r.deleted} 个项目${r.failed ? `，失败 ${r.failed}` : ''}`, 'success');
      setClassifyPicked(new Set());
      await pollClassify();
      load();
    } catch (e: any) {
      toast('删除失败：' + (e?.response?.data?.error || e.message), 'error');
    }
  };
  const closeClassify = () => {
    stopClassifyPoll();
    setClassifyOpen(false);
  };

  // —— 单个：重新审计 / 重新验证 / 重跑全流程 ——
  const onReaudit = async (id: string) => {
    if (!confirm('重新进行代码审计将清空该项目已有的审计与验证结果，确定？')) return;
    try {
      await api.reaudit(id);
      toast('已重新发起代码审计', 'success');
    } catch (e: any) {
      toast('操作失败：' + (e?.response?.data?.error || e.message), 'error');
    }
    load();
  };
  const onReverify = async (id: string) => {
    if (!confirm('重新进行靶机验证将清空已有验证结果，确定？')) return;
    try {
      await api.reverify(id, { verify_history: false });
      toast('已重新发起靶机验证', 'success');
    } catch (e: any) {
      toast('操作失败：' + (e?.response?.data?.error || e.message), 'error');
    }
    load();
  };
  const onReverifyChain = async (id: string) => {
    if (
      !confirm(
        '仅重跑组合利用链验证？将复用已有单漏洞验证结果，只重新构造并实测组合链（无权限 / 低权限 → RCE；不做管理员 → RCE），结果在「远程验证·组合」显示。确定？'
      )
    )
      return;
    try {
      await api.reverifyChain(id);
      toast('已发起组合链验证（远程验证·组合）', 'success');
    } catch (e: any) {
      toast('操作失败：' + (e?.response?.data?.error || e.message), 'error');
    }
    load();
  };
  const onRefull = async (id: string) => {
    if (!confirm('重跑全流程将清空所有结果并重新进行代码审计 + 靶机验证，确定？')) return;
    try {
      await api.refull(id);
      toast('已重新发起全流程（审计 + 验证）', 'success');
    } catch (e: any) {
      toast('操作失败：' + (e?.response?.data?.error || e.message), 'error');
    }
    load();
  };
  const onReingest = async (id: string) => {
    try {
      const res = await api.reingest(id);
      toast(`已从磁盘重新汇总，共 ${res?.count ?? 0} 个漏洞`, 'success');
    } catch (e: any) {
      toast('重新汇总失败：' + (e?.response?.data?.error || e.message), 'error');
    }
    load();
  };
  const onReprocess = async (id: string) => {
    if (
      !confirm(
        '将复用已有的专项子智能体审计结果，跳过重新扫描源码，仅重跑「AI 智能去重 → 代码级验证 → 红队实战二次评级」。确定？'
      )
    )
      return;
    try {
      await api.reprocess(id);
      toast('已发起重跑（复用子智能体结果，去重/验证/评级）', 'success');
    } catch (e: any) {
      toast('操作失败：' + (e?.response?.data?.error || e.message), 'error');
    }
    load();
  };

  // 功能1：对该项目发起"改动最大版本批量审计"（打开弹窗）
  const onBatchVersions = (p: Project) => setBatchTarget(p);

  // 行内编辑项目名 / 版本号（便于版本对比）。乐观更新 + 失败回滚。
  const saveMeta = async (id: string, fields: ProjectMetaPatch) => {
    const prev = projects;
    setProjects((list) =>
      list.map((p) => (p.id === id ? { ...p, ...fields } : p))
    );
    try {
      await api.updateProject(id, fields);
      toast('已保存', 'success');
    } catch (e: any) {
      setProjects(prev);
      toast('保存失败：' + (e?.response?.data?.error || e.message), 'error');
    }
  };

  // —— 批量：重新审计 / 重新验证 / 重跑全流程 ——
  const bulkReaudit = async () => {
    const ids = [...selected];
    if (!confirm(`对选中的 ${ids.length} 个项目重新代码审计？将清空其审计与验证结果`)) return;
    try {
      const res = await api.bulkReaudit(ids);
      toast(`已重新发起 ${res?.count ?? ids.length} 个代码审计`, 'success');
    } catch (e: any) {
      toast('批量重新审计失败：' + (e?.response?.data?.error || e.message), 'error');
    }
    load();
  };
  const bulkReverify = async () => {
    const ids = [...selected];
    if (
      !confirm(
        `对选中的 ${ids.length} 个项目重新靶机验证？将清空其验证结果（未完成审计的会跳过）`
      )
    )
      return;
    try {
      const res = await api.bulkReverify(ids, { verify_history: false });
      const skip = res?.skipped ? `，${res.skipped} 个未完成审计已跳过` : '';
      toast(`已重新发起 ${res?.count ?? 0} 个靶机验证${skip}`, res?.count ? 'success' : 'info');
    } catch (e: any) {
      toast('批量重新验证失败：' + (e?.response?.data?.error || e.message), 'error');
    }
    load();
  };
  const bulkReverifyChain = async () => {
    const ids = [...selected];
    if (
      !confirm(
        `对选中的 ${ids.length} 个项目仅重跑组合链验证？复用已有单漏洞结果，只重新实测组合链（无权限 / 低权限 → RCE；不做管理员 → RCE），结果在「远程验证·组合」显示（未完成审计的会跳过）`
      )
    )
      return;
    try {
      const res = await api.bulkReverifyChain(ids);
      const skip = res?.skipped ? `，${res.skipped} 个未完成审计已跳过` : '';
      toast(`已发起 ${res?.count ?? 0} 个组合链验证${skip}`, res?.count ? 'success' : 'info');
    } catch (e: any) {
      toast('批量组合链验证失败：' + (e?.response?.data?.error || e.message), 'error');
    }
    load();
  };
  const bulkRefull = async () => {
    const ids = [...selected];
    if (!confirm(`对选中的 ${ids.length} 个项目重跑全流程？将清空所有结果并重新审计 + 验证`)) return;
    try {
      const res = await api.bulkRefull(ids);
      toast(`已重新发起 ${res?.count ?? ids.length} 个全流程任务`, 'success');
    } catch (e: any) {
      toast('批量全流程失败：' + (e?.response?.data?.error || e.message), 'error');
    }
    load();
  };
  const bulkReprocess = async () => {
    const ids = [...selected];
    if (
      !confirm(
        `对选中的 ${ids.length} 个项目复用子智能体结果重跑？跳过重新扫源码，仅重跑 去重→代码级验证→二次评级`
      )
    )
      return;
    try {
      const res = await api.bulkReprocess(ids);
      toast(`已发起 ${res?.count ?? ids.length} 个重跑（复用结果）`, 'success');
    } catch (e: any) {
      toast('批量重跑失败：' + (e?.response?.data?.error || e.message), 'error');
    }
    load();
  };
  const bulkReingest = async () => {
    const ids = [...selected];
    if (!confirm(`对选中的 ${ids.length} 个项目从磁盘重新汇总结果？（不重跑 Pi，把已有产物纳入库存）`))
      return;
    try {
      const res = await api.bulkReingest(ids);
      toast(
        `已重新汇总 ${res?.count ?? 0} 个项目，共纳入 ${res?.totalVulns ?? 0} 个漏洞`,
        res?.count ? 'success' : 'info'
      );
    } catch (e: any) {
      toast('批量重新汇总失败：' + (e?.response?.data?.error || e.message), 'error');
    }
    load();
  };

  const onReconcileIdleContainers = async () => {
    const verifyPipeline =
      statusFilter === 'verify_running' ||
      statusFilter === 'verify_queued' ||
      statusFilter === 'active';
    const runningN = filterCounts.verify_running ?? 0;
    const msg = verifyPipeline
      ? `将停止除当前验证中（共 ${runningN} 个）及环境搭建中外的 Code Docker 靶机（验证排队不保留容器）。继续？`
      : '将停止不在验证中/审计/搭建白名单内的闲置 Docker 靶机。继续？';
    if (!confirm(msg)) return;
    setReconcilingContainers(true);
    try {
      const res = await api.reconcileIdleContainers(verifyPipeline);
      const errN = res.errors?.length ?? 0;
      toast(
        `已保留 ${res.kept.length} 个靶机，停止 ${res.stopped.length} 个${errN ? `，${errN} 个失败` : ''}`,
        res.stopped.length > 0 || errN > 0 ? 'success' : 'info'
      );
    } catch (e: any) {
      toast('清理闲置靶机失败：' + (e?.response?.data?.error || e.message), 'error');
    } finally {
      setReconcilingContainers(false);
    }
  };

  const rowToggle = useEventCallback(toggle);
  const rowToggleAll = useEventCallback(toggleAll);
  const rowOpen = useEventCallback((id: string) => navigate(`/projects/${id}`));
  const rowSaveMeta = useEventCallback(saveMeta);
  const rowPause = useEventCallback(onPause);
  const rowResume = useEventCallback(onResume);
  const rowBatchVersions = useEventCallback(onBatchVersions);
  const rowReaudit = useEventCallback(onReaudit);
  const rowReverify = useEventCallback(onReverify);
  const rowReverifyChain = useEventCallback(onReverifyChain);
  const rowRefull = useEventCallback(onRefull);
  const rowReprocess = useEventCallback(onReprocess);
  const rowReingest = useEventCallback(onReingest);
  const rowDelete = useEventCallback(onDelete);
  const classifyPick = useEventCallback(toggleClassifyPick);

  const emptyHint = useMemo(() => {
    if (statusFilter !== 'verify_running') return null;
    const queuedN = filterCounts.verify_queued ?? 0;
    if (queuedN <= 0) return null;
    return (
      <>
        当前没有正在跑 Pi 验证的任务；另有{' '}
        <button type="button" className="text-link-btn" onClick={() => applyStatusFilter('verify_queued')}>
          {queuedN} 个项目在验证排队中
        </button>
        （审计槽位满时会优先让验证任务启动）。
      </>
    );
  }, [statusFilter, filterCounts.verify_queued]);

  return (
    <div className="projects-page">
      <div className="page-head projects-head">
        <div>
          <h1>审计列表</h1>
          <p>查看与管理全部代码安全审计任务</p>
        </div>
        <button
          className="btn btn-secondary classify-launch-btn"
          onClick={openClassify}
          title="用 LLM 逐个判定项目是否含 Web 端，非 Web 的先预览再清理"
        >
          批量判定非 Web 并清理
        </button>
        {(statusFilter === 'verify_running' ||
          statusFilter === 'verify_queued' ||
          statusFilter === 'active') && (
          <button
            className="btn btn-secondary"
            onClick={onReconcileIdleContainers}
            disabled={reconcilingContainers}
            title="保留验证中及环境搭建中的项目靶机，停止其余闲置 Docker 容器（验证排队不保留）"
          >
            {reconcilingContainers ? '清理中…' : '清理闲置靶机'}
          </button>
        )}
      </div>

      <div className="list-toolbar">
        <ProjectSearch onQueryChange={onSearchQueryChange} />
        <div className="status-filter">
          <div
            className={'sfilter-dropdown' + (activeMenuOpen ? ' open' : '')}
            ref={activeMenuRef}
          >
            <button
              type="button"
              className={
                'sfilter sfilter-split-main' +
                (isActiveGroupFilter(statusFilter) ? ' active' : '')
              }
              onClick={() => applyStatusFilter('active')}
              title="全部进行中的审计与验证"
            >
              {activeButtonLabel}
              <span className="sfilter-count">{filterCounts.active ?? 0}</span>
            </button>
            <button
              type="button"
              className={
                'sfilter sfilter-split-caret' +
                (isActiveGroupFilter(statusFilter) ? ' active' : '')
              }
              aria-expanded={activeMenuOpen}
              aria-label="展开进行中子状态"
              onClick={(e) => {
                e.stopPropagation();
                setActiveMenuOpen((v) => !v);
              }}
            >
              ▾
            </button>
            {activeMenuOpen && (
              <div className="sfilter-menu" role="menu">
                {ACTIVE_MENU.map((m) => (
                  <button
                    key={m.key}
                    type="button"
                    role="menuitem"
                    className={'sfilter-menu-item' + (statusFilter === m.key ? ' selected' : '')}
                    onClick={() => applyStatusFilter(m.key)}
                  >
                    {m.label}
                    <span className="sfilter-count">{filterCounts[m.key] ?? 0}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
          <div
            className={'sfilter-dropdown' + (doneMenuOpen ? ' open' : '')}
            ref={doneMenuRef}
          >
            <button
              type="button"
              className={
                'sfilter sfilter-split-main' + (isDoneGroupFilter(statusFilter) ? ' active' : '')
              }
              onClick={() => applyStatusFilter(doneMainFilter)}
              title={
                statusFilter === 'remote_done'
                  ? '远程验证已完成的项目（大屏「已完成项目」）'
                  : '全部已完成的审计与验证'
              }
            >
              {doneButtonLabel}
              <span className="sfilter-count">{doneButtonCount}</span>
            </button>
            <button
              type="button"
              className={
                'sfilter sfilter-split-caret' + (isDoneGroupFilter(statusFilter) ? ' active' : '')
              }
              aria-expanded={doneMenuOpen}
              aria-label="展开完成子状态"
              onClick={(e) => {
                e.stopPropagation();
                setDoneMenuOpen((v) => !v);
              }}
            >
              ▾
            </button>
            {doneMenuOpen && (
              <div className="sfilter-menu sfilter-menu-wide" role="menu">
                {DONE_MENU.map((m) => (
                  <button
                    key={m.key}
                    type="button"
                    role="menuitem"
                    className={'sfilter-menu-item' + (statusFilter === m.key ? ' selected' : '')}
                    onClick={() => applyStatusFilter(m.key)}
                  >
                    {m.label}
                    <span className="sfilter-count">{filterCounts[m.key] ?? 0}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
          <div
            className={'sfilter-dropdown' + (pausedMenuOpen ? ' open' : '')}
            ref={pausedMenuRef}
          >
            <button
              type="button"
              className={
                'sfilter sfilter-split-main' + (isPausedGroupFilter(statusFilter) ? ' active' : '')
              }
              onClick={() => applyStatusFilter('paused')}
              title="全部已暂停的审计与验证"
            >
              {pausedButtonLabel}
              <span className="sfilter-count">{filterCounts.paused ?? 0}</span>
            </button>
            <button
              type="button"
              className={
                'sfilter sfilter-split-caret' + (isPausedGroupFilter(statusFilter) ? ' active' : '')
              }
              aria-expanded={pausedMenuOpen}
              aria-label="展开已暂停子状态"
              onClick={(e) => {
                e.stopPropagation();
                setPausedMenuOpen((v) => !v);
              }}
            >
              ▾
            </button>
            {pausedMenuOpen && (
              <div className="sfilter-menu sfilter-menu-wide" role="menu">
                {PAUSED_MENU.map((m) => (
                  <button
                    key={m.key}
                    type="button"
                    role="menuitem"
                    className={'sfilter-menu-item' + (statusFilter === m.key ? ' selected' : '')}
                    onClick={() => applyStatusFilter(m.key)}
                  >
                    {m.label}
                    <span className="sfilter-count">{filterCounts[m.key] ?? 0}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
          {FILTERS.map((f) => {
            const count = filterCounts[f.key] ?? 0;
            return (
              <button
                key={f.key}
                className={'sfilter' + (statusFilter === f.key ? ' active' : '')}
                onClick={() => applyStatusFilter(f.key)}
              >
                {f.label}
                <span className="sfilter-count">{count}</span>
              </button>
            );
          })}
        </div>
        <div className="group-toggle" title="审计列表分组方式">
          <span className="group-label">分组</span>
          {GROUP_OPTIONS.map((g) => (
            <button
              key={g.key}
              className={'gbtn' + (groupBy === g.key ? ' active' : '')}
              onClick={() => setGroupBy(g.key)}
            >
              {g.label}
            </button>
          ))}
        </div>
        {selected.size > 0 && (
          <div className="bulk-bar">
            <span>已选 {selected.size} 项</span>
            <button
              className="btn btn-primary"
              onClick={bulkResume}
              disabled={continuableSelected === 0}
              title="继续选中的已暂停 / 失败任务"
            >
              批量继续{continuableSelected > 0 ? ` (${continuableSelected})` : ''}
            </button>
            <button className="btn btn-secondary" onClick={bulkPause}>
              批量暂停
            </button>
            <RerunMenu
              label="批量重跑 ▾"
              onAudit={bulkReaudit}
              onVerify={bulkReverify}
              onVerifyChain={bulkReverifyChain}
              onFull={bulkRefull}
              onReprocess={bulkReprocess}
              onReingest={bulkReingest}
              canVerify
            />
            <button className="btn btn-danger" onClick={bulkDelete}>
              批量删除
            </button>
          </div>
        )}
      </div>

      <div className="card table-card project-list-card">
        <VirtualProjectList
          entries={listEntries}
          resetKey={`${statusFilter}\u0000${querySearch}\u0000${page}\u0000${pageSize}\u0000${groupBy}`}
          selected={selected}
          allSelected={allSelected}
          emptyContent={
            listLoading
              ? '项目列表加载中…'
              : emptyHint ??
                (projects.length === 0
                  ? '暂无项目，点击左下角"新建审计"发起'
                  : '当前筛选条件下没有项目')
          }
          onToggle={rowToggle}
          onToggleAll={rowToggleAll}
          onOpen={rowOpen}
          onSaveMeta={rowSaveMeta}
          onPause={rowPause}
          onResume={rowResume}
          onBatchVersions={rowBatchVersions}
          onReaudit={rowReaudit}
          onReverify={rowReverify}
          onReverifyChain={rowReverifyChain}
          onRefull={rowRefull}
          onReprocess={rowReprocess}
          onReingest={rowReingest}
          onDelete={rowDelete}
        />
        <Pager
          total={total}
          page={curPage}
          totalPages={totalPages}
          pageSize={pageSize}
          onPage={setPage}
          onPageSize={setPageSize}
        />
      </div>

      {batchTarget && (
        <BatchVersionsModal
          project={batchTarget}
          onClose={() => setBatchTarget(null)}
          onDone={(msg, type) => {
            toast(msg, type);
            setBatchTarget(null);
            load();
          }}
        />
      )}

      {nextStepTarget && (
        <NextStepModal
          project={nextStepTarget}
          onClose={() => setNextStepTarget(null)}
          onChoose={onChooseNextStep}
        />
      )}

      {delProgress && (
        <div className="del-overlay">
          <div className="del-modal">
            <div className="del-spinner" />
            <h3>正在删除项目</h3>
            <div className="del-bar">
              <div
                className="del-bar-fill"
                style={{
                  width: `${
                    delProgress.total
                      ? Math.round((delProgress.done / delProgress.total) * 100)
                      : 0
                  }%`,
                }}
              />
            </div>
            <div className="del-meta">
              <span>
                {delProgress.done} / {delProgress.total}
              </span>
              {delProgress.current && (
                <span className="del-current ellipsis" title={delProgress.current}>
                  {delProgress.current}
                </span>
              )}
            </div>
          </div>
        </div>
      )}

      {classifyOpen && (
        <div className="del-overlay">
          <div className="classify-modal">
            <div className="classify-head">
              <h3>批量判定非 Web 并清理</h3>
              <button className="btn btn-ghost" onClick={closeClassify}>
                关闭
              </button>
            </div>

            {(() => {
              const s = classifyStatus;
              const phase = s?.phase ?? 'idle';
              if (!s || phase === 'idle') {
                return (
                  <div className="classify-body">
                    <p className="classify-hint">
                      对全库所有项目用 LLM 逐个判定是否含 Web 端：未判定的首判、已判定的强制重判。
                      未克隆的项目会先克隆并建图，属于长任务。判定完成后会列出「无 Web 端」清单，
                      <strong>由你勾选后再批量删除</strong>（删除记录进回收站，不支持还原）。
                    </p>
                    <div className="classify-actions">
                      <button className="btn btn-primary" onClick={startClassify}>
                        开始判定
                      </button>
                    </div>
                  </div>
                );
              }

              const pct = s.total ? Math.round((s.done / s.total) * 100) : 0;
              const running = phase === 'classifying';
              const awaiting = phase === 'awaiting_confirm' || phase === 'done';
              return (
                <div className="classify-body">
                  <div className="classify-progress">
                    <div className="del-bar">
                      <div className="del-bar-fill" style={{ width: `${pct}%` }} />
                    </div>
                    <div className="classify-stats">
                      <span>
                        进度 {s.done} / {s.total}
                      </span>
                      <span>含 Web {s.web}</span>
                      <span>非 Web {s.nonWeb.length}</span>
                      {s.deleted > 0 && <span>已删除 {s.deleted}</span>}
                      {s.skipped.length > 0 && <span>跳过(忙) {s.skipped.length}</span>}
                      {s.failed.length > 0 && <span>失败 {s.failed.length}</span>}
                      {running && (
                        <span>
                          进行中 {s.running}
                          {s.concurrency != null ? ` / 并发 ${s.concurrency}` : ''}
                        </span>
                      )}
                    </div>
                  </div>

                  {running && (
                    <div className="classify-actions">
                      <span className="classify-hint">判定进行中…（可随时取消，已判定结果会保留）</span>
                      <button className="btn btn-danger" onClick={cancelClassify}>
                        取消判定
                      </button>
                    </div>
                  )}

                  {awaiting && (
                    <>
                      <div className="classify-candidates-head">
                        <strong>判定为「无 Web 端」的项目（{s.nonWeb.length}）</strong>
                        {s.nonWeb.length > 0 && (
                          <label className="classify-selall">
                            <input
                              type="checkbox"
                              checked={classifyPicked.size === s.nonWeb.length}
                              onChange={(e) =>
                                setClassifyPicked(
                                  e.target.checked
                                    ? new Set(s.nonWeb.map((c) => c.id))
                                    : new Set()
                                )
                              }
                            />
                            全选
                          </label>
                        )}
                      </div>
                      {s.nonWeb.length === 0 ? (
                        <div className="classify-empty">没有判定为无 Web 端的项目。</div>
                      ) : (
                        <VirtualClassifyList
                          candidates={s.nonWeb}
                          picked={classifyPicked}
                          onToggle={classifyPick}
                        />
                      )}
                      <div className="classify-actions">
                        <button className="btn btn-secondary" onClick={startClassify}>
                          重新判定
                        </button>
                        <button
                          className="btn btn-danger"
                          onClick={confirmClassifyDelete}
                          disabled={classifyPicked.size === 0}
                        >
                          删除选中（{classifyPicked.size}）
                        </button>
                      </div>
                    </>
                  )}
                </div>
              );
            })()}
          </div>
        </div>
      )}
    </div>
  );
}

/** 搜索展示值留在叶子组件中，父列表只在静默 250ms 后收到查询值。 */
const ProjectSearch = memo(function ProjectSearch({
  onQueryChange,
}: {
  onQueryChange: (value: string) => void;
}) {
  const [displayValue, setDisplayValue] = useState('');

  useEffect(() => {
    const timer = window.setTimeout(() => onQueryChange(displayValue), 250);
    return () => window.clearTimeout(timer);
  }, [displayValue, onQueryChange]);

  return (
    <div className="search-box">
      <span className="search-icon" aria-hidden="true">
        ⌕
      </span>
      <input
        className="input search-input"
        aria-label="搜索项目"
        placeholder="搜索项目名称或压缩包名称…"
        value={displayValue}
        onChange={(event) => setDisplayValue(event.target.value)}
      />
    </div>
  );
});

type ProjectRowHandlers = {
  onToggle: (id: string) => void;
  onOpen: (id: string) => void;
  onSaveMeta: (id: string, fields: ProjectMetaPatch) => void | Promise<void>;
  onPause: (id: string) => void | Promise<void>;
  onResume: (project: Project) => void | Promise<void>;
  onBatchVersions: (project: Project) => void;
  onReaudit: (id: string) => void | Promise<void>;
  onReverify: (id: string) => void | Promise<void>;
  onReverifyChain: (id: string) => void | Promise<void>;
  onRefull: (id: string) => void | Promise<void>;
  onReprocess: (id: string) => void | Promise<void>;
  onReingest: (id: string) => void | Promise<void>;
  onDelete: (id: string) => void | Promise<void>;
};

type VirtualProjectListProps = ProjectRowHandlers & {
  entries: ProjectListEntry[];
  resetKey: string;
  selected: Set<string>;
  allSelected: boolean;
  emptyContent: ReactNode;
  onToggleAll: () => void;
};

const PROJECT_ROW_ESTIMATE = 68;
const PROJECT_GROUP_ESTIMATE = 42;
const PROJECT_LIST_MAX_HEIGHT = 620;

function VirtualProjectList({
  entries,
  resetKey,
  selected,
  allSelected,
  emptyContent,
  onToggleAll,
  ...rowHandlers
}: VirtualProjectListProps) {
  const viewportRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    viewportRef.current?.scrollTo({ top: 0 });
  }, [resetKey]);
  const getItemKey = useCallback(
    (index: number) => entries[index]?.key ?? index,
    [entries]
  );
  const virtualizer = useVirtualizer({
    count: entries.length,
    getScrollElement: () => viewportRef.current,
    estimateSize: (index) =>
      entries[index]?.kind === 'group' ? PROJECT_GROUP_ESTIMATE : PROJECT_ROW_ESTIMATE,
    getItemKey,
    overscan: 6,
  });
  const estimatedHeight = useMemo(
    () =>
      entries.reduce(
        (height, entry) =>
          height +
          (entry.kind === 'group' ? PROJECT_GROUP_ESTIMATE : PROJECT_ROW_ESTIMATE),
        0
      ),
    [entries]
  );
  const viewportHeight =
    entries.length === 0
      ? 104
      : Math.min(PROJECT_LIST_MAX_HEIGHT, Math.max(PROJECT_ROW_ESTIMATE, estimatedHeight));

  return (
    <div className="project-grid-x-scroll">
      <div
        className="project-grid-shell"
        role="table"
        aria-label="审计项目列表"
        aria-rowcount={entries.length + 1}
      >
        <div className="project-grid-header" role="row">
          <div className="project-grid-cell col-check" role="columnheader">
            <input
              type="checkbox"
              aria-label="选择当前页全部项目"
              checked={allSelected}
              onChange={onToggleAll}
            />
          </div>
          <div className="project-grid-cell" role="columnheader">项目名称</div>
          <div className="project-grid-cell" role="columnheader">系统名</div>
          <div className="project-grid-cell" role="columnheader">版本号</div>
          <div className="project-grid-cell" role="columnheader">状态</div>
          <div className="project-grid-cell" role="columnheader">漏洞</div>
          <div className="project-grid-cell" role="columnheader">耗时</div>
          <div className="project-grid-cell" role="columnheader">开始时间</div>
          <div className="project-grid-cell col-actions" role="columnheader">操作</div>
        </div>
        <div
          ref={viewportRef}
          className="project-grid-viewport"
          style={{ height: viewportHeight }}
        >
          {entries.length === 0 ? (
            <div className="empty-row project-grid-empty">{emptyContent}</div>
          ) : (
            <div
              className="project-grid-virtual-canvas"
              style={{ height: virtualizer.getTotalSize() }}
            >
              {virtualizer.getVirtualItems().map((virtualItem) => {
                const entry = entries[virtualItem.index];
                return (
                  <div
                    key={entry.key}
                    ref={virtualizer.measureElement}
                    data-index={virtualItem.index}
                    className="project-virtual-item"
                    style={{ transform: `translateY(${virtualItem.start}px)` }}
                  >
                    {entry.kind === 'group' ? (
                      <div className="project-grid-group" role="row">
                        <span className="group-title">{entry.label}</span>
                        <span className="group-count">{entry.count}</span>
                      </div>
                    ) : (
                      <ProjectRow
                        project={entry.project}
                        selected={selected.has(entry.project.id)}
                        {...rowHandlers}
                      />
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

const ProjectRow = memo(function ProjectRow({
  project: p,
  selected,
  onToggle,
  onOpen,
  onSaveMeta,
  onPause,
  onResume,
  onBatchVersions,
  onReaudit,
  onReverify,
  onReverifyChain,
  onRefull,
  onReprocess,
  onReingest,
  onDelete,
}: ProjectRowHandlers & { project: Project; selected: boolean }) {
  return (
    <div className={`project-grid-row${selected ? ' row-selected' : ''}`} role="row">
      <div className="project-grid-cell col-check" role="cell">
        <input
          type="checkbox"
          aria-label={`选择项目 ${p.project_name}`}
          checked={selected}
          onChange={() => onToggle(p.id)}
        />
      </div>
      <div className="project-grid-cell" role="cell">
        <EditableCell
          value={p.project_name}
          ariaLabel="项目名称"
          onSave={(value) => onSaveMeta(p.id, { project_name: value })}
          onOpen={() => onOpen(p.id)}
          display={<span className="proj-name">{p.project_name}</span>}
        />
      </div>
      <div className="project-grid-cell" role="cell">
        <EditableCell
          value={p.system_name || ''}
          ariaLabel="系统名"
          placeholder="设置系统名"
          onSave={(value) => onSaveMeta(p.id, { system_name: value.trim() || null })}
          display={
            p.system_name ? (
              <span className="system-badge">{p.system_name}</span>
            ) : (
              <span className="muted">—</span>
            )
          }
        />
      </div>
      <div className="project-grid-cell" role="cell">
        <EditableCell
          value={p.source_version || ''}
          ariaLabel="版本号"
          placeholder="设置版本号"
          onSave={(value) => onSaveMeta(p.id, { source_version: value.trim() || null })}
          display={
            p.source_version ? (
              <span className="version-badge">{p.source_version}</span>
            ) : (
              <span className="muted">—</span>
            )
          }
        />
      </div>
      <div className="project-grid-cell" role="cell">
        <PhaseBadge status={p.status} verifyStatus={p.verify_status} />
      </div>
      <div className="project-grid-cell" role="cell">
        <VulnPills p={p} />
      </div>
      <div className="project-grid-cell muted dur-cell" role="cell">
        <span title="代码审计累计耗时">审 {fmtDuration(p.audit_duration_ms)}</span>
        <span title="远程验证累计耗时">验 {fmtDuration(p.verify_duration_ms)}</span>
      </div>
      <div
        className="project-grid-cell muted"
        role="cell"
        title="审计开始时间"
      >
        {fmtDateMinute(p.started_at)}
      </div>
      <div className="project-grid-cell col-actions project-grid-actions" role="cell">
        <button className="btn btn-ghost" onClick={() => onOpen(p.id)}>
          查看
        </button>
        {canPause(p) ? (
          <button className="btn btn-ghost" onClick={() => onPause(p.id)}>
            暂停
          </button>
        ) : (
          (canContinue(p) || needsNextStep(p)) && (
            <button className="btn btn-ghost" onClick={() => onResume(p)}>
              继续
            </button>
          )
        )}
        <button
          className="btn btn-ghost"
          onClick={() => onBatchVersions(p)}
          title="对该项目近几年改动最大的 TopN 个版本批量审计（基于 GitHub 版本对比）"
        >
          多版本审计
        </button>
        <RerunMenu
          label="重跑 ▾"
          onAudit={() => onReaudit(p.id)}
          onVerify={() => onReverify(p.id)}
          onVerifyChain={() => onReverifyChain(p.id)}
          onFull={() => onRefull(p.id)}
          onReprocess={() => onReprocess(p.id)}
          onReingest={() => onReingest(p.id)}
          canVerify={p.status === 'completed'}
        />
        <button className="btn btn-ghost danger-text" onClick={() => onDelete(p.id)}>
          删除
        </button>
      </div>
    </div>
  );
});

function VirtualClassifyList({
  candidates,
  picked,
  onToggle,
}: {
  candidates: WebClassifyCandidate[];
  picked: Set<string>;
  onToggle: (id: string) => void;
}) {
  const viewportRef = useRef<HTMLDivElement>(null);
  const getItemKey = useCallback(
    (index: number) => candidates[index]?.id ?? index,
    [candidates]
  );
  const virtualizer = useVirtualizer({
    count: candidates.length,
    getScrollElement: () => viewportRef.current,
    estimateSize: () => 42,
    getItemKey,
    overscan: 6,
  });

  return (
    <div
      ref={viewportRef}
      className="classify-list"
      role="list"
      style={{ height: Math.min(320, Math.max(42, candidates.length * 42)) }}
    >
      <div
        className="classify-virtual-canvas"
        style={{ height: virtualizer.getTotalSize() }}
      >
        {virtualizer.getVirtualItems().map((virtualItem) => {
          const candidate = candidates[virtualItem.index];
          return (
            <div
              key={candidate.id}
              ref={virtualizer.measureElement}
              data-index={virtualItem.index}
              className="classify-virtual-item"
              style={{ transform: `translateY(${virtualItem.start}px)` }}
            >
              <ClassifyCandidateRow
                candidate={candidate}
                checked={picked.has(candidate.id)}
                isLast={virtualItem.index === candidates.length - 1}
                onToggle={onToggle}
              />
            </div>
          );
        })}
      </div>
    </div>
  );
}

const ClassifyCandidateRow = memo(function ClassifyCandidateRow({
  candidate,
  checked,
  isLast,
  onToggle,
}: {
  candidate: WebClassifyCandidate;
  checked: boolean;
  isLast: boolean;
  onToggle: (id: string) => void;
}) {
  return (
    <label className={`classify-item${isLast ? ' is-last' : ''}`} role="listitem">
      <input
        type="checkbox"
        checked={checked}
        onChange={() => onToggle(candidate.id)}
      />
      <span className="ci-name" title={candidate.name}>
        {candidate.name}
      </span>
      <span className="ci-source ellipsis" title={candidate.source_link}>
        {candidate.source_link}
      </span>
    </label>
  );
});

/** 分页控件：每页数量选择（10/30/50）+ 上/下一页 + 页码指示。 */
function Pager({
  total,
  page,
  totalPages,
  pageSize,
  onPage,
  onPageSize,
}: {
  total: number;
  page: number;
  totalPages: number;
  pageSize: number;
  onPage: (p: number) => void;
  onPageSize: (n: number) => void;
}) {
  if (total === 0) return null;
  const from = (page - 1) * pageSize + 1;
  const to = Math.min(page * pageSize, total);
  return (
    <div className="pager">
      <span className="pager-info">
        共 {total} 个 · 第 {from}–{to} 个
      </span>
      <div className="pager-size">
        <span className="pager-label">每页</span>
        {[10, 30, 50].map((n) => (
          <button
            key={n}
            className={'pager-size-btn' + (pageSize === n ? ' active' : '')}
            onClick={() => onPageSize(n)}
          >
            {n}
          </button>
        ))}
      </div>
      <div className="pager-nav">
        <button className="pager-btn" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          上一页
        </button>
        <span className="pager-cur">
          {page} / {totalPages}
        </span>
        <button className="pager-btn" disabled={page >= totalPages} onClick={() => onPage(page + 1)}>
          下一页
        </button>
      </div>
    </div>
  );
}

function RerunMenu({
  label,
  onAudit,
  onVerify,
  onVerifyChain,
  onFull,
  onReprocess,
  onReingest,
  canVerify,
}: {
  label: string;
  onAudit: () => void;
  onVerify: () => void;
  onVerifyChain: () => void;
  onFull: () => void;
  onReprocess: () => void;
  onReingest: () => void;
  canVerify: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState({ top: 0, left: 0, visible: false });
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const updatePosition = useCallback(() => {
    const trigger = triggerRef.current;
    const menu = menuRef.current;
    if (!trigger || !menu) return;
    const anchor = trigger.getBoundingClientRect();
    const width = menu.offsetWidth || 276;
    const height = menu.offsetHeight || 310;
    const gap = 6;
    const viewportGap = 8;
    const opensAbove =
      anchor.bottom + gap + height > window.innerHeight - viewportGap &&
      anchor.top >= height + gap + viewportGap;
    const top = opensAbove
      ? Math.max(viewportGap, anchor.top - height - gap)
      : Math.max(
          viewportGap,
          Math.min(window.innerHeight - height - viewportGap, anchor.bottom + gap)
        );
    const left = Math.max(
      viewportGap,
      Math.min(window.innerWidth - width - viewportGap, anchor.right - width)
    );
    setPosition({ top, left, visible: true });
  }, []);

  useLayoutEffect(() => {
    if (!open) return;
    updatePosition();
    const onPointerDown = (event: PointerEvent) => {
      const target = event.target as Node;
      if (
        !triggerRef.current?.contains(target) &&
        !menuRef.current?.contains(target)
      ) {
        setOpen(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setOpen(false);
        triggerRef.current?.focus();
      }
    };
    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    window.addEventListener('resize', updatePosition);
    window.addEventListener('scroll', updatePosition, true);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
      window.removeEventListener('resize', updatePosition);
      window.removeEventListener('scroll', updatePosition, true);
    };
  }, [open, updatePosition]);

  const pick = (fn: () => void) => {
    setOpen(false);
    fn();
  };

  return (
    <span className="rerun">
      <button
        ref={triggerRef}
        type="button"
        className="btn btn-ghost rerun-summary"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => {
          setPosition((current) => ({ ...current, visible: false }));
          setOpen((current) => !current);
        }}
      >
        {label}
      </button>
      {open &&
        createPortal(
          <div
            ref={menuRef}
            className="rerun-menu rerun-menu-portal"
            role="menu"
            style={{
              top: position.top,
              left: position.left,
              visibility: position.visible ? 'visible' : 'hidden',
            }}
          >
            <button type="button" role="menuitem" onClick={() => pick(onAudit)}>
              重新代码审计
            </button>
            <button
              type="button"
              role="menuitem"
              onClick={() => pick(onVerify)}
              disabled={!canVerify}
              title={canVerify ? '重新靶机验证' : '需先完成代码审计'}
            >
              重新靶机验证
            </button>
            <button
              type="button"
              role="menuitem"
              onClick={() => pick(onVerifyChain)}
              disabled={!canVerify}
              title={canVerify ? '仅重跑组合利用链验证（复用已有单漏洞结果，穷尽构造无权限 / 低权限 → RCE 组合链；不做管理员 → RCE），结果在「远程验证·组合」显示' : '需先完成代码审计'}
            >
              远程验证·组合（仅组合链）
            </button>
            <button type="button" role="menuitem" onClick={() => pick(onFull)}>
              重新全流程
            </button>
            <div className="rerun-sep" />
            <button
              type="button"
              role="menuitem"
              onClick={() => pick(onReprocess)}
              title="复用已有专项子智能体结果，跳过重新扫源码，仅重跑 去重→代码级验证→二次评级"
            >
              复用结果重跑(去重/验证/评级)
            </button>
            <button
              type="button"
              role="menuitem"
              onClick={() => pick(onReingest)}
              title="不重跑 Pi，把工作区已有产物重新纳入库存"
            >
              重新汇总(不重跑)
            </button>
          </div>,
          document.body
        )}
    </span>
  );
}

function EditableCell({
  value,
  display,
  ariaLabel,
  placeholder,
  onSave,
  onOpen,
}: {
  value: string;
  display: ReactNode;
  ariaLabel: string;
  placeholder?: string;
  onSave: (v: string) => void | Promise<void>;
  onOpen?: () => void;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (editing) {
      setDraft(value);
      inputRef.current?.focus();
      inputRef.current?.select();
    }
  }, [editing]);

  const commit = () => {
    setEditing(false);
    if (draft !== value) void onSave(draft);
  };
  const cancel = () => {
    setEditing(false);
    setDraft(value);
  };

  if (editing) {
    return (
      <input
        ref={inputRef}
        className="input cell-edit-input"
        aria-label={ariaLabel}
        placeholder={placeholder}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === 'Enter') {
            e.preventDefault();
            commit();
          } else if (e.key === 'Escape') {
            e.preventDefault();
            cancel();
          }
        }}
      />
    );
  }

  return (
    <div className="cell-editable">
      <span
        className={onOpen ? 'cell-open' : undefined}
        onClick={onOpen}
        title={onOpen ? '点击查看详情' : undefined}
      >
        {display}
      </span>
      <button
        type="button"
        className="cell-edit-btn"
        title={`编辑${ariaLabel}`}
        aria-label={`编辑${ariaLabel}`}
        onClick={() => setEditing(true)}
      >
        ✎
      </button>
    </div>
  );
}

function VulnPills({ p }: { p: Project }) {
  const total = totalVulns(p);
  if (total === 0) return <span className="muted">—</span>;
  return (
    <div className="vuln-pills">
      {p.count_critical > 0 && (
        <span className="vp" style={{ background: 'var(--sev-critical)' }}>
          {p.count_critical}
        </span>
      )}
      {p.count_high > 0 && (
        <span className="vp" style={{ background: 'var(--sev-high)' }}>
          {p.count_high}
        </span>
      )}
      {p.count_medium > 0 && (
        <span className="vp" style={{ background: 'var(--sev-medium)' }}>
          {p.count_medium}
        </span>
      )}
      {p.count_low > 0 && (
        <span className="vp" style={{ background: 'var(--sev-low)' }}>
          {p.count_low}
        </span>
      )}
      {p.count_info > 0 && (
        <span className="vp" style={{ background: 'var(--sev-info)' }}>
          {p.count_info}
        </span>
      )}
    </div>
  );
}

const YEAR_OPTIONS = [1, 2, 3];
const TOPN_OPTIONS = [3, 5, 10];

function BatchVersionsModal({
  project,
  onClose,
  onDone,
}: {
  project: Project;
  onClose: () => void;
  onDone: (msg: string, type: 'success' | 'error' | 'info') => void;
}) {
  const isGithub = project.source_type === 'github';
  const [years, setYears] = useState(1);
  const [topN, setTopN] = useState(5);
  const [githubUrl, setGithubUrl] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  const submit = async () => {
    if (!isGithub && !githubUrl.trim()) {
      setErr('请填写该项目的 GitHub 地址');
      return;
    }
    setBusy(true);
    setErr('');
    try {
      const res = await api.batchVersions(project.id, {
        years,
        topN,
        githubUrl: isGithub ? undefined : githubUrl.trim(),
      });
      const skip = res.skipped?.length ? `，跳过 ${res.skipped.length} 个已存在版本` : '';
      onDone(
        `已创建 ${res.created.length} 个版本审计任务${skip}`,
        res.created.length ? 'success' : 'info'
      );
    } catch (e: any) {
      setErr(e?.response?.data?.error || e?.message || '发起失败');
      setBusy(false);
    }
  };

  return (
    <div className="del-overlay" onClick={onClose}>
      <div className="bv-modal" onClick={(e) => e.stopPropagation()}>
        <h3>审计改动最大的版本</h3>
        <p className="bv-sub">
          基于 GitHub 版本对比，挑选「{project.system_name || project.project_name}」近几年代码改动最大的版本批量审计（自动排除当前版本
          {project.source_version ? ` ${project.source_version}` : ''}）。
        </p>

        {!isGithub && (
          <div className="bv-field">
            <label>GitHub 地址（压缩包项目必填）</label>
            <input
              className="input"
              placeholder="https://github.com/owner/repo"
              value={githubUrl}
              onChange={(e) => setGithubUrl(e.target.value)}
            />
          </div>
        )}

        <div className="bv-field">
          <label>时间范围</label>
          <div className="bv-opts">
            {YEAR_OPTIONS.map((y) => (
              <button
                key={y}
                className={'bv-opt' + (years === y ? ' active' : '')}
                onClick={() => setYears(y)}
              >
                近 {y} 年
              </button>
            ))}
          </div>
        </div>

        <div className="bv-field">
          <label>版本数量</label>
          <div className="bv-opts">
            {TOPN_OPTIONS.map((n) => (
              <button
                key={n}
                className={'bv-opt' + (topN === n ? ' active' : '')}
                onClick={() => setTopN(n)}
              >
                Top {n}
              </button>
            ))}
          </div>
        </div>

        {err && <div className="bv-err">{err}</div>}

        <div className="bv-actions">
          <button className="btn btn-secondary" onClick={onClose} disabled={busy}>
            取消
          </button>
          <button className="btn btn-primary" onClick={submit} disabled={busy}>
            {busy ? '正在分析版本…' : '开始批量审计'}
          </button>
        </div>
        <p className="bv-hint">
          提示：该操作会调用 GitHub API 对比相邻版本改动量，建议在「设置」中配置 GitHub Token 以避免限流。
        </p>
      </div>
    </div>
  );
}
