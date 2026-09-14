import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useVirtualizer } from '@tanstack/react-virtual';
import { api } from '../lib/api';
import { wsClient } from '../lib/ws';
import type {
  Project,
  Vulnerability,
  AgentEvent,
  Severity,
  ExploitReport,
  ExploitItem,
  ExploitChain,
  ChainStep,
  ExploitVersion,
  HistoricalVersionResult,
  AuthRequired,
  ExploitStatus,
  VerificationProgress,
} from '../lib/types';
import { StatusBadge, SeverityBadge, RedTeamValueBadge } from '../components/Badges';
import AgentFlow from '../components/AgentFlow';
import NextStepModal from '../components/NextStepModal';
import { fmtTime, fmtDuration, SEVERITY_ORDER, SEVERITY_LABEL, REALTEAM_LABEL } from '../lib/format';
import { subagentCountForLanguage } from '../lib/subagents';
import './ProjectDetail.css';

const ENV_LABEL: Record<string, string> = {
  building: '靶机环境搭建中',
  ready: '靶机环境就绪',
  failed: '靶机环境搭建失败',
};

function envBadgeLabel(status: string): string {
  return ENV_LABEL[status] || status;
}

// 从后端拉取的事件条数上限：不传 limit 时一次审计可返回 3000+ 条（>1MB JSON），
// 浏览器 parse 会把主线程卡死；已拉取的事件由虚拟列表按需挂载 DOM。
const EVENT_FETCH_LIMIT = 800;
// 内存中保留的实时事件条数上限：长时间挂在详情页时，WS 会持续追加事件使数组无限增长，
// 每次 flush 的大数组拷贝 + LogPanel useMemo 重建会拖慢主线程。虚拟列表只按需挂载 DOM，
// 故只保留最近 N 条即可（更早记录仍可通过导出报告查看）。
const MAX_LIVE_EVENTS = 4000;
// 高频 WS 事件（流式 token/事件追加）的批量刷新间隔（毫秒）：攒一波再一次性 setState，
// 避免每个 token 都触发整组件重渲染。
const FLUSH_INTERVAL_MS = 150;
// 远程验证进度（exploit_progress）触发的整表重拉节流间隔（毫秒）。
const RELOAD_THROTTLE_MS = 1500;
// 验证进行中，完整利用报告（可达数 MB）的刷新节流间隔（毫秒）：进度计数用轻量接口高频刷新，
// 而重量级 exploit-report 只按更长间隔刷新，避免每 1.5s 拉整份报告 + 重建派生 Tab 卡住主线程。
const REPORT_REFRESH_MS = 8000;
// 漏洞列表每个严重度分组默认最多渲染的条数：超出折叠，点击"展开全部"再渲染剩余，
// 避免一次性把 400+ 行漏洞（含逐行按钮）全塞进 DOM（C6）。
const VULN_GROUP_CAP = 60;

type ResultTab = 'all' | 'single' | 'single_fail' | 'single_hist' | 'chain' | 'chain_hist';
type ExploitWithVuln = { ex: ExploitItem; vuln?: Vulnerability };

interface ExploitDerived {
  singleSuccess: ExploitItem[];
  singleNotSuccess: ExploitItem[];
  singleSuccessByAuth: { none: ExploitWithVuln[]; user: ExploitWithVuln[]; admin: ExploitWithVuln[] };
  chmCount: number;
  verifiedWithResult: number;
  pendingCount: number;
  failedCount: number;
  restrictedCount: number;
  chainSuccessList: ExploitChain[];
  chainFailedList: ExploitChain[];
  chainTotal: number;
  chainVerifiedCount: number;
  chainSuccessCount: number;
  chainRestrictedCount: number;
  chainFailedOnlyCount: number;
  chainFailedCount: number;
  chainPendingCount: number;
  chainRestrictedList: ExploitChain[];
  chainFailedOnlyList: ExploitChain[];
  chainPendingList: ExploitChain[];
  allChains: ExploitChain[];
  singleHistSuccess: ExploitItem[];
  chainHistSuccess: ExploitChain[];
  parsedSummary: { intro: string; chains: ExploitChain[] };
  singleFailedWithVuln: ExploitWithVuln[];
  singleRestrictedWithVuln: ExploitWithVuln[];
  singlePendingWithVuln: ExploitWithVuln[];
  singleHistWithVuln: ExploitWithVuln[];
}

type VulnerabilityDisplayRow =
  | { kind: 'item'; key: string; vuln: Vulnerability }
  | {
      kind: 'cluster';
      key: string;
      clusterId: string;
      faces: Vulnerability[];
      total: number;
    };

interface VulnerabilityIndex {
  all: Vulnerability[];
  bySeverity: Record<Severity, Vulnerability[]>;
  chm: Vulnerability[];
  order: Map<Vulnerability, number>;
  exactTitle: Map<string, Vulnerability>;
  fullTitleByLength: Map<number, Map<string, Vulnerability>>;
  substringFirstByLength: Map<number, Map<string, Vulnerability>>;
  titleLengths: number[];
  clusterById: Map<string, Vulnerability[]>;
  displayRows: Record<
    Severity,
    { collapsed: VulnerabilityDisplayRow[]; expanded: VulnerabilityDisplayRow[] }
  >;
}

const KIND_META: Record<string, { label: string; icon: string }> = {
  system: { label: '系统', icon: '◍' },
  text: { label: '分析', icon: '✎' },
  tool_use: { label: '工具', icon: '⚙' },
  agent_start: { label: '派发', icon: '⎇' },
  tool_result: { label: '结果', icon: '↩' },
  result: { label: '完成', icon: '✓' },
  error: { label: '错误', icon: '✕' },
};

const VERIFY_META: Record<string, { label: string; color: string }> = {
  queued: { label: '验证排队中', color: 'var(--accent-amber)' },
  running: { label: '验证中', color: 'var(--accent-teal)' },
  paused: { label: '验证已暂停', color: 'var(--warning)' },
  completed: { label: '验证完成', color: 'var(--success)' },
  failed: { label: '验证失败', color: 'var(--error)' },
};

function VerifyBadge({ status }: { status: string }) {
  const m = VERIFY_META[status];
  if (!m) return null;
  return (
    <span
      className="badge"
      style={{ background: `color-mix(in srgb, ${m.color} 16%, transparent)`, color: m.color }}
    >
      <span
        style={{ width: 6, height: 6, borderRadius: '50%', background: m.color, display: 'inline-block' }}
      />
      {m.label}
    </span>
  );
}

export default function ProjectDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [project, setProject] = useState<Project | null>(null);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [events, setEvents] = useState<AgentEvent[]>([]);
  /** 流程图阶段锚点（system 里程碑），与 tail events 合并后供 AgentFlow 判定，避免 limit 截断导致阶段回退。 */
  const [anchorEvents, setAnchorEvents] = useState<AgentEvent[]>([]);
  const [liveText, setLiveText] = useState('');
  const [activeVuln, setActiveVuln] = useState<Vulnerability | null>(null);
  const [activeExploit, setActiveExploit] = useState<ExploitItem | null>(null);
  const [exploitReport, setExploitReport] = useState<ExploitReport | null>(null);
  const [verificationProgress, setVerificationProgress] = useState<VerificationProgress | null>(null);
  const [loadingProject, setLoadingProject] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [resultTab, setResultTab] = useState<ResultTab>('all');
  const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>({});
  const [sevViewFilter, setSevViewFilter] = useState<Severity | 'all'>('all');
  const [authSevFilter, setAuthSevFilter] = useState<{
    none: Severity | 'all';
    user: Severity | 'all';
    admin: Severity | 'all';
  }>({
    none: 'all',
    user: 'all',
    admin: 'all',
  });
  // 「继续 → 下一步」选择框开关（仅代码审计完成后点继续时弹出）。
  const [nextStepOpen, setNextStepOpen] = useState(false);
  // —— 高频 WS 事件批量刷新缓冲区（C2）——
  const pendingEventsRef = useRef<AgentEvent[]>([]);
  const liveTextRef = useRef('');
  const liveTextDirtyRef = useRef(false);
  const flushTimerRef = useRef<number | null>(null);
  // —— reload 节流（C4）——
  const lastReloadRef = useRef(0);
  const reloadTimerRef = useRef<number | null>(null);
  // —— 验证中利用报告刷新节流：进度计数高频刷、重量级报告长间隔刷 ——
  const lastReportRef = useRef(0);
  const reportTimerRef = useRef<number | null>(null);
  const mountedRef = useRef(true);
  const reloadSeqRef = useRef(0);
  const reloadAbortRef = useRef<AbortController | null>(null);
  // 首屏 compact 请求的 promise：用于把重载荷（事件/锚点/利用报告）延后到它之后再发。
  const compactPromiseRef = useRef<Promise<unknown> | null>(null);
  // —— 事件重同步：仅在阶段【切入 running】的边沿触发一次全量重拉，避免 running 期间每条 WS 消息都重拉 800 条事件 ——
  const runningRef = useRef(false);

  const reload = useCallback(() => {
    if (!id) return;
    reloadAbortRef.current?.abort();
    const controller = new AbortController();
    reloadAbortRef.current = controller;
    const seq = ++reloadSeqRef.current;
    lastReloadRef.current = Date.now();
    // 不清空已有 loadError：成功时再清。避免重试过程中错误闪没、失败又永久转圈。
    // 首屏关键路径：只有 compact（元数据 + 紧凑漏洞索引）决定 loading 何时结束。
    const compactP = api
      .getProjectCompact(id, controller.signal)
      .then((d) => {
        if (seq !== reloadSeqRef.current) return;
        setLoadError('');
        setProject(d.project);
        runningRef.current =
          d.project?.status === 'running' || d.project?.verify_status === 'running';
        setVulns(
          d.vulnerabilities.map((v) => ({
            ...v,
            description: v.description ?? '',
            recommendation: v.recommendation ?? '',
            code_snippet: v.code_snippet ?? '',
            taint_chain: v.taint_chain ?? '',
          }))
        );
      })
      .catch((error: any) => {
        if (seq === reloadSeqRef.current && error?.code !== 'ERR_CANCELED') {
          const timedOut =
            error?.code === 'ECONNABORTED' || /timeout/i.test(String(error?.message || ''));
          setLoadError(
            timedOut
              ? '后端响应超时（可能正在处理审计日志）。请稍后重试，无需刷新整个页面。'
              : error?.response?.data?.error || error?.message || '项目详情加载失败'
          );
        }
      })
      .finally(() => {
        if (seq === reloadSeqRef.current) setLoadingProject(false);
      });
    // 验证进度很轻量，可与 compact 并行。
    void api
      .getProjectVerificationProgress(id, controller.signal)
      .then((progress) => {
        if (seq === reloadSeqRef.current) setVerificationProgress(progress);
      })
      .catch(() => {
        // 旧后端兼容：权威进度接口不可用时继续使用报告派生统计。
      });
    // 完整利用报告可达数 MB，延后到 compact 之后再取，避免与首屏关键请求抢连接/DB 锁。
    compactPromiseRef.current = compactP;
    void compactP.then(() => {
      if (seq !== reloadSeqRef.current || controller.signal.aborted) return;
      void api
        .getProjectExploitReport(id, controller.signal)
        .then((report) => {
          if (seq === reloadSeqRef.current)
            setExploitReport((report as ExploitReport | null) ?? null);
        })
        .catch(() => {
          if (seq === reloadSeqRef.current) setExploitReport(null);
        });
    });
  }, [id]);

  const fetchEvents = () => (id ? api.getEvents(id, EVENT_FETCH_LIMIT) : Promise.resolve([]));
  const fetchAnchors = () => (id ? api.getEventAnchors(id) : Promise.resolve([]));
  const syncEvents = () =>
    Promise.all([fetchEvents(), fetchAnchors()]).then(([list, anchors]) => {
      setAnchorEvents(anchors);
      applyServerEvents(list);
    });

  // 远程验证进度高频推送时，用节流合并整表重拉，避免每批都重拉 400+ 漏洞并重渲染。
  const throttledReload = () => {
    const elapsed = Date.now() - lastReloadRef.current;
    if (elapsed >= RELOAD_THROTTLE_MS) {
      reload();
    } else if (reloadTimerRef.current == null) {
      reloadTimerRef.current = window.setTimeout(() => {
        reloadTimerRef.current = null;
        reload();
      }, RELOAD_THROTTLE_MS - elapsed);
    }
  };

  // 只刷新轻量验证进度计数（不碰重量级 exploit-report）。
  const refreshProgressOnly = () => {
    if (!id) return;
    void api
      .getProjectVerificationProgress(id)
      .then((progress) => {
        if (mountedRef.current) setVerificationProgress(progress);
      })
      .catch(() => {
        /* 旧后端兼容：忽略 */
      });
  };

  // 重量级利用报告刷新（含派生 Tab 重建），按 REPORT_REFRESH_MS 长间隔节流。
  const throttledReportRefresh = () => {
    if (!id) return;
    const run = () => {
      lastReportRef.current = Date.now();
      void api
        .getProjectExploitReport(id)
        .then((report) => {
          if (mountedRef.current) setExploitReport((report as ExploitReport | null) ?? null);
        })
        .catch(() => {
          /* 忽略瞬时错误，下一次节流窗口再试 */
        });
    };
    const elapsed = Date.now() - lastReportRef.current;
    if (elapsed >= REPORT_REFRESH_MS) {
      run();
    } else if (reportTimerRef.current == null) {
      reportTimerRef.current = window.setTimeout(() => {
        reportTimerRef.current = null;
        run();
      }, REPORT_REFRESH_MS - elapsed);
    }
  };

  // 把缓冲区里累积的事件/流式文本一次性刷入 state（C2）。
  const flushPending = () => {
    flushTimerRef.current = null;
    if (pendingEventsRef.current.length > 0) {
      const batch = pendingEventsRef.current;
      pendingEventsRef.current = [];
      setEvents((prev) => {
        const merged = prev.length + batch.length > MAX_LIVE_EVENTS ? [...prev, ...batch] : null;
        if (merged) return merged.slice(-MAX_LIVE_EVENTS);
        return [...prev, ...batch];
      });
    }
    if (liveTextDirtyRef.current) {
      liveTextDirtyRef.current = false;
      setLiveText(liveTextRef.current);
    }
  };
  const scheduleFlush = () => {
    if (flushTimerRef.current != null) return;
    flushTimerRef.current = window.setTimeout(flushPending, FLUSH_INTERVAL_MS);
  };
  // 服务端权威事件列表覆盖本地时，清空未刷入的缓冲，避免重复/错乱。
  const applyServerEvents = (list: AgentEvent[]) => {
    pendingEventsRef.current = [];
    liveTextRef.current = '';
    liveTextDirtyRef.current = false;
    setLiveText('');
    setEvents(list);
  };

  // —— 流程模块单独运行入口 ——
  const runAction = async (label: string, confirmMsg: string, fn: () => Promise<unknown>) => {
    if (!confirm(confirmMsg)) return;
    try {
      await fn();
      fetchEvents().then(setEvents);
    } catch (e: any) {
      alert(`${label}失败：${e?.response?.data?.error || e?.message || e}`);
    }
    reload();
  };
  const onReaudit = () =>
    runAction('重新审计', '重新进行代码审计将清空已有审计与验证结果，从头跑最多 4 路专项子智能体，确定？', () =>
      api.reaudit(id!)
    );
  const onReprocess = () =>
    runAction(
      '复用结果重跑',
      '复用已有专项子智能体结果，跳过重新扫源码，仅重跑「AI 智能去重 → 代码级验证 → 红队实战二次评级」，确定？',
      () => api.reprocess(id!)
    );
  const onStartVerify = async () => {
    if (!project) return;
    const started = project.verify_status !== 'none';
    const label = started ? '重跑远程验证' : '远程靶机验证';
    const confirmMsg = started
      ? '将清空已有验证结果并重新开始靶机验证，确定？'
      : '将对全部中高危漏洞做远程实测，确定？';
    if (!confirm(confirmMsg)) return;
    try {
      if (started) await api.reverify(project.id, { verify_history: false });
      else await api.verify(project.id, { verify_history: false });
      reload();
    } catch (e: any) {
      alert(`${label}失败：${e?.response?.data?.error || e?.message || e}`);
    }
  };
  // 「继续 → 下一步」选择框：审计完成的仅代码审计项目发起靶机验证（无二次 confirm）。
  const onChooseNextStep = async () => {
    if (!project) return;
    setNextStepOpen(false);
    try {
      await api.verify(project.id, { verify_history: false });
      reload();
    } catch (e: any) {
      alert(`发起验证失败：${e?.response?.data?.error || e?.message || e}`);
    }
  };
  const STAGE_LABEL: Record<string, string> = {
    subagent: '语言专项并发审计',
    dedup: 'AI 智能去重',
    codeverify: '代码级验证',
    regrade: '红队二次评级',
    env: '靶机环境搭建',
    remote: '远程验证',
    chain: '组合验证',
  };
  const onRunStage = (stage: string, mode: 'only' | 'from', opts?: { verify_history?: boolean }) => {
    const name = STAGE_LABEL[stage] || stage;
    const msg =
      mode === 'only'
        ? `仅重跑「${name}」这一个环节，确定？`
        : `从「${name}」开始，依次跑到本流程末尾（会连跑后续环节并保持数据一致），确定？`;
    return runAction('分环节运行', msg, () =>
      api.runStage(id!, stage, mode, opts?.verify_history)
    );
  };
  const onOpenVuln = useCallback(
    (vuln: Vulnerability, exploit?: ExploitItem) => {
      setActiveVuln(vuln);
      setActiveExploit(exploit ?? null);
      if (!id) return;
      void api
        .getProjectVulnerability(id, vuln.id)
        .then((detail) => {
          setActiveVuln((current) => (current?.id === detail.id ? detail : current));
        })
        .catch(() => {
          // 紧凑索引已足够显示标题/定位；详情请求失败时保留当前弹窗。
        });
    },
    [id]
  );

  // 手动清除靶机（item 11）
  const onClearEnv = () =>
    runAction('清除靶机', '将彻底移除该项目的 Docker 靶机环境（容器/卷）。验证完靶机默认只停止不删除、便于二次验证；确认清除？', () =>
      api.clearEnv(id!)
    );
  const onRetryEnv = () =>
    runAction('重试环境搭建', '将清除失败状态并重新排队靶机预搭建（与代码审计并行，不占审计槽）。确认？', () =>
      api.retryEnv(id!)
    );

  // —— 派生数据统一 useMemo 缓存（C3）：仅在依赖变化时重算，避免每个流式 token 重渲染时重复计算 ——
  // 合并锚点 + 尾部事件（按 id 去重），供流程图正确识别已被 limit 截掉的早期里程碑。
  const flowEvents = useMemo(() => {
    const byId = new Map<string, AgentEvent>();
    for (const e of anchorEvents) byId.set(e.id, e);
    for (const e of events) byId.set(e.id, e);
    return [...byId.values()].sort((a, b) => a.ts - b.ts);
  }, [anchorEvents, events]);
  const auditEvents = useMemo(
    () => flowEvents.filter((e) => (e.phase ?? 'audit') === 'audit'),
    [flowEvents]
  );
  const verifyEvents = useMemo(() => flowEvents.filter((e) => e.phase === 'verify'), [flowEvents]);

  // 一次构建严重度、cluster 与规范化标题索引，供列表和利用结果共同复用。
  const vulnerabilityIndex = useMemo(() => buildVulnerabilityIndex(vulns), [vulns]);

  const exploitDerived = useMemo<ExploitDerived>(() => {
    // 标题匹配走预建索引，不再为每个利用项线性扫描全部漏洞。
    const findVuln = (name: unknown): Vulnerability | undefined =>
      findIndexedVulnerability(name, vulnerabilityIndex);
    const sevRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const withVuln = (list: ExploitItem[]) =>
      list
        .map((ex) => ({ ex, vuln: findVuln(ex.vulnerability) }))
        .sort((a, b) => sevRank[a.vuln?.severity ?? 'info'] - sevRank[b.vuln?.severity ?? 'info']);

    // 只在远程验证列表里展示 严重/高危/中危 的漏洞：低危/信息/实战无 本就不进远程验证，
    // 若出现（多为验证后又被二次评级下调的历史残留），一律从远程验证结果里过滤掉。
    // 无法匹配到漏洞的（标题漂移）保留——它们本就是被验证过的在范围内条目。
    const inScope = ({ vuln }: { vuln?: Vulnerability }) =>
      !vuln || ['critical', 'high', 'medium'].includes(vuln.severity);

    const normExploitStatus = (entry: ExploitItem): ExploitStatus => remoteStatusOf(entry);

    const successWV = withVuln(
      (exploitReport?.exploits ?? []).filter((e) => normExploitStatus(e) === 'success')
    ).filter(inScope);
    const failWV = withVuln(
      (exploitReport?.exploits ?? []).filter((e) => normExploitStatus(e) !== 'success')
    ).filter(inScope);
    const histWV = withVuln(
      (exploitReport?.exploits ?? []).filter((e) =>
        asHistArray(e.historical_verification).some((h) => h.status === 'success')
      )
    ).filter(inScope);

    // 按「成功利用所需的最低权限」把远程验证成功的单漏洞分三档：无权限 / 低权限(用户或注册) / 管理员。
    // 一个漏洞若在 none 成功即归 none；无 none 成功但 user 成功归 user；仅 admin 成功归 admin。
    // 旧数据无 privilege_results 时，以现有 auth_required 兜底；auth_required 缺失时用文本启发式判断是否无权限。
    const tierOf = ({ ex }: { ex: ExploitItem }): AuthRequired => {
      const pr = ex.privilege_results;
      if (pr) {
        if (pr.none?.status === 'success') return 'none';
        if (pr.user?.status === 'success') return 'user';
        if (pr.admin?.status === 'success') return 'admin';
      }
      if (ex.auth_required === 'none' || ex.auth_required === 'user' || ex.auth_required === 'admin') {
        return ex.auth_required;
      }
      // 兜底：无结构化权限时，按验证记录文本判断是否无权限，否则保守归为低权限。
      return isUnauth(ex.auth_required, formatExploitText(ex.local_result), formatExploitText(ex.detail))
        ? 'none'
        : 'user';
    };
    const groupByAuth = (withV: { ex: ExploitItem; vuln?: Vulnerability }[]) => {
      const none: ExploitWithVuln[] = [];
      const user: ExploitWithVuln[] = [];
      const admin: ExploitWithVuln[] = [];
      for (const item of withV) {
        const tier = tierOf(item);
        if (tier === 'none') none.push(item);
        else if (tier === 'admin') admin.push(item);
        else user.push(item);
      }
      return { none, user, admin };
    };
    const singleSuccessByAuth = groupByAuth(successWV);
    const chmCount = vulnerabilityIndex.chm.length;
    const singleSuccess = successWV.map((x) => x.ex);
    const singleNotSuccess = failWV.map((x) => x.ex);
    const singleFailedWithVuln = failWV.filter(({ ex }) => normExploitStatus(ex) === 'failed');
    const singleRestrictedWithVuln = failWV.filter(
      ({ ex }) => normExploitStatus(ex) === 'restricted'
    );
    const singlePendingWithVuln = failWV.filter(({ ex }) => normExploitStatus(ex) === 'unknown');
    const singleHistSuccess = histWV.map((x) => x.ex);
    const verifiedWithResult = successWV.length + singleFailedWithVuln.length + singleRestrictedWithVuln.length;
    // 待验证优先用报告里的 unknown；若报告未对齐/为空，用 CHM 缺口兜底，避免进度条卡死不动
    const pendingCount = Math.max(
      singlePendingWithVuln.length,
      Math.max(0, chmCount - verifiedWithResult)
    );
    const failedCount = singleFailedWithVuln.length;
    const restrictedCount = singleRestrictedWithVuln.length;
    // 每个已落盘的组合链都需要可见；失败、受限、未知和解析失败同样是验证结论。
    // 展示前先清洗 detail/steps/status，避免对象型字段渲染白屏。
    const allChains = (exploitReport?.chains ?? []).map(sanitizeChainForDisplay);
    const parsedSummary =
      allChains.length === 0
        ? parseSummaryChains(exploitReport?.summary ?? '')
        : { intro: '', chains: [] as ExploitChain[] };
    // 链池 = 报告 chains + summary 兜底；验证过程中发现新链时 allChains 增长，统计随之更新
    const chainPool =
      allChains.length > 0
        ? allChains
        : parsedSummary.chains.map(sanitizeChainForDisplay);
    const normChainStatus = (c: ExploitChain) => normalizeExploitStatus(c.status);
    const chainSuccessList = chainPool.filter((c) => normChainStatus(c) === 'success');
    const chainRestrictedList = chainPool.filter((c) => normChainStatus(c) === 'restricted');
    const chainFailedOnlyList = chainPool.filter((c) => normChainStatus(c) === 'failed');
    const chainFailedList = chainPool.filter((c) => {
      const s = normChainStatus(c);
      return s === 'failed' || s === 'restricted';
    });
    const chainPendingList = chainPool.filter((c) => normChainStatus(c) === 'unknown');
    const chainTotal = chainPool.length;
    const chainVerifiedCount = chainSuccessList.length + chainFailedList.length;
    const chainSuccessCount = chainSuccessList.length;
    const chainRestrictedCount = chainRestrictedList.length;
    const chainFailedOnlyCount = chainFailedOnlyList.length;
    const chainFailedCount = chainFailedList.length;
    const chainPendingCount = chainPendingList.length;
    const chainHistSuccess = (exploitReport?.chains ?? [])
      .map(sanitizeChainForDisplay)
      .filter(
        (c) => asHistArray(c.historical_verification).some((h) => h.status === 'success')
      );
    // 预计算 render 内会用到的 withVuln 结果（已过滤低危/信息），避免渲染期重复 map+sort
    const singleHistWithVuln = histWV;
    return {
      singleSuccess,
      singleNotSuccess,
      singleSuccessByAuth,
      chmCount,
      verifiedWithResult,
      pendingCount,
      failedCount,
      restrictedCount,
      chainSuccessList,
      chainFailedList,
      chainTotal,
      chainVerifiedCount,
      chainSuccessCount,
      chainRestrictedCount,
      chainFailedOnlyCount,
      chainFailedCount,
      chainPendingCount,
      chainRestrictedList,
      chainFailedOnlyList,
      chainPendingList,
      allChains,
      singleHistSuccess,
      chainHistSuccess,
      parsedSummary,
      singleFailedWithVuln,
      singleRestrictedWithVuln,
      singlePendingWithVuln,
      singleHistWithVuln,
    };
  }, [exploitReport, vulnerabilityIndex]);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    if (!id) return;
    reload();
    // 日志事件（最近 800 条）+ 阶段锚点延后到 compact 返回之后再取，避免与首屏关键请求争抢。
    void (compactPromiseRef.current ?? Promise.resolve()).then(() => {
      syncEvents();
    });

    const unsub = wsClient.subscribe((msg) => {
      if (msg.type === 'hello') {
        reload();
        return;
      }
      if (msg.projectId !== id) return;
      if (msg.type === 'agent_event') {
        const ev = msg.event as AgentEvent;
        // 高频路径：不直接 setState，先写缓冲区，由 scheduleFlush 每 ~150ms 批量刷新一次（C2）。
        if (ev.kind === 'delta') {
          liveTextRef.current = (liveTextRef.current + ev.text).slice(-600);
          liveTextDirtyRef.current = true;
          scheduleFlush();
          return;
        }
        liveTextRef.current = '';
        liveTextDirtyRef.current = true;
        pendingEventsRef.current.push(ev);
        scheduleFlush();
      } else if (msg.type === 'project_status') {
        const envStatus = (msg as { env_status?: string }).env_status;
        setProject((p) => {
          if (!p) return p;
          const statusChanged = msg.status !== undefined && msg.status !== p.status;
          const verifyChanged =
            msg.verify_status !== undefined && msg.verify_status !== p.verify_status;
          const nextEnvStatus = envStatus as Project['env_status'] | undefined;
          const envChanged = nextEnvStatus !== undefined && nextEnvStatus !== p.env_status;
          const errorInMsg = Object.prototype.hasOwnProperty.call(msg, 'error_message');
          const verifyErrInMsg = Object.prototype.hasOwnProperty.call(msg, 'verify_error');
          const nextError = errorInMsg
            ? ((msg as { error_message?: string | null }).error_message ?? null)
            : statusChanged && (msg.status === 'running' || msg.status === 'queued')
              ? null
              : p.error_message;
          const nextVerifyErr = verifyErrInMsg
            ? ((msg as { verify_error?: string | null }).verify_error ?? null)
            : verifyChanged && (msg.verify_status === 'running' || msg.verify_status === 'queued')
              ? null
              : p.verify_error;
          if (
            !statusChanged &&
            !verifyChanged &&
            !envChanged &&
            nextError === p.error_message &&
            nextVerifyErr === p.verify_error
          ) {
            return p;
          }
          const next = { ...p };
          if (statusChanged) next.status = msg.status;
          if (verifyChanged) next.verify_status = msg.verify_status;
          if (envChanged) next.env_status = nextEnvStatus!;
          next.error_message = nextError;
          next.verify_error = nextVerifyErr;
          return next;
        });
        // 新一轮（重）审计/验证【切入 running 的边沿】：后端已清空旧事件，前端重拉一次做同步。
        // 关键修复：只在「上一刻非 running → 现在 running」的边沿重拉，而不是 running 期间【每条】
        // project_status 消息都重拉 800 条事件（那会造成持续 setEvents→整页重渲染的风暴，表现为白屏卡顿）。
        const nowRunning = msg.status === 'running' || msg.verify_status === 'running';
        if (nowRunning && !runningRef.current) {
          syncEvents();
        }
        runningRef.current = nowRunning;
        // 远程验证增量进度：后端每完成一批就落盘部分 exploit_report 并推送此标志。
        // 轻量进度计数高频刷新（让 x/y 实时走动），重量级利用报告按长间隔节流刷新
        // （逐批 Tab 仍会更新，只是不再每 1.5s 拉整份报告 + 重建派生列表把主线程卡住）。
        if ((msg as { exploit_progress?: boolean }).exploit_progress) {
          refreshProgressOnly();
          throttledReportRefresh();
          return;
        }
        const terminal = ['completed', 'failed', 'paused'];
        // 环境就绪/失败时刷新以拿到 target_url 等完整信息
        if (
          terminal.includes(msg.status) ||
          terminal.includes(msg.verify_status) ||
          envStatus === 'ready' ||
          envStatus === 'failed'
        )
          reload();
      }
    }, { scope: 'projects', projectId: id });
    return () => {
      unsub();
      reloadAbortRef.current?.abort();
      if (flushTimerRef.current != null) {
        clearTimeout(flushTimerRef.current);
        flushTimerRef.current = null;
      }
      if (reloadTimerRef.current != null) {
        clearTimeout(reloadTimerRef.current);
        reloadTimerRef.current = null;
      }
      if (reportTimerRef.current != null) {
        clearTimeout(reportTimerRef.current);
        reportTimerRef.current = null;
      }
    };
  }, [id]);

  const auditRunning =
    !!project && (project.status === 'running' || project.status === 'queued');
  const effectiveVerifyStatus = auditRunning ? 'none' : (project?.verify_status ?? 'none');

  if (!project && loadError) {
    return (
      <div className="card load-error-card" role="alert">
        <h2>项目详情暂时无法加载</h2>
        <p className="muted">{loadError}</p>
        <button
          className="btn btn-primary"
          onClick={() => {
            setLoadingProject(true);
            reload();
          }}
        >
          重新加载
        </button>
      </div>
    );
  }
  if (loadingProject && !project) {
    return (
      <div className="detail-page" aria-busy="true">
        <div className="card loading">正在加载项目摘要与验证进度…</div>
        <div className="card loading">正在加载漏洞索引…</div>
      </div>
    );
  }
  if (!project) {
    return (
      <div className="card load-error-card" role="alert">
        <h2>项目详情暂时无法加载</h2>
        <p className="muted">请求已结束但未拿到项目数据，请重试。</p>
        <button
          className="btn btn-primary"
          onClick={() => {
            setLoadingProject(true);
            reload();
          }}
        >
          重新加载
        </button>
      </div>
    );
  }

  const verifyRunning =
    effectiveVerifyStatus === 'running' || effectiveVerifyStatus === 'queued';
  const envBuilding = project.env_status === 'building';
  const canPauseAudit = auditRunning;
  const canResumeAudit = project.status === 'paused' || project.status === 'failed';
  const auditDone = project.status === 'completed';
  // 仅代码审计、审计已完成、尚未做靶机验证：点「继续」应弹出下一步选择框（与列表页一致）。
  const needsNextStep =
    project.status === 'completed' &&
    project.verify_status === 'none' &&
    project.opt_auto_verify === 0;
  const remoteVerifyActive =
    effectiveVerifyStatus === 'running' || effectiveVerifyStatus === 'completed';
  const verifyStarted = effectiveVerifyStatus !== 'none';
  const isHarnessVerify = String(project.target_url || '').startsWith('harness://');
  const clientVerifyRuntime = ((): string => {
    const col = String(project.opt_verify_runtime || '').trim();
    if (col === 'mini' || col === 'full') return 'full';
    if (col === 'none') return 'none';
    if (String(project.target_url || '').startsWith('mini://')) return 'full';
    if (project.opt_auto_verify === 1) return 'full';
    return '';
  })();
  // 历史版本验证已从 Flash 产品面移除，不展示对应页签与结果。
  const historyEnabled = false;
  const verifyFlowRunning = auditRunning ? envBuilding : verifyRunning || envBuilding;

  const grouped = vulnerabilityIndex.bySeverity;
  const {
    singleSuccess,
    singleNotSuccess,
    singleSuccessByAuth,
    chmCount: derivedChmCount,
    verifiedWithResult: derivedVerifiedWithResult,
    pendingCount: derivedPendingCount,
    failedCount: derivedFailedCount,
    restrictedCount: derivedRestrictedCount,
    singleHistSuccess,
    chainHistSuccess,
    chainSuccessList,
    chainTotal,
    chainVerifiedCount,
    chainSuccessCount,
    chainRestrictedCount,
    chainFailedOnlyCount,
    chainPendingCount,
    chainRestrictedList,
    chainFailedOnlyList,
    chainPendingList,
    parsedSummary,
    singleFailedWithVuln,
    singleRestrictedWithVuln,
    singlePendingWithVuln,
    singleHistWithVuln,
  } = exploitDerived;
  const chmCount = verificationProgress?.total ?? derivedChmCount;
  const verifiedWithResult = verificationProgress?.concluded ?? derivedVerifiedWithResult;
  const pendingCount = verificationProgress
    ? verificationProgress.pending + verificationProgress.queued + verificationProgress.running
    : derivedPendingCount;
  const failedCount = verificationProgress
    ? verificationProgress.failed
    : derivedFailedCount;
  const restrictedCount = verificationProgress
    ? verificationProgress.restricted
    : derivedRestrictedCount;
  const timeoutCount = verificationProgress?.timeout ?? 0;
  const successCount = verificationProgress?.success ?? singleSuccess.length;
  const notSuccessCount = verificationProgress
    ? Math.max(0, verificationProgress.total - verificationProgress.success)
    : singleNotSuccess.length;
  const chainPhaseActive =
    verifyRunning &&
    !isHarnessVerify &&
    pendingCount === 0 &&
    chmCount > 0 &&
    verifiedWithResult >= chmCount;

  return (
    <div className="detail-page">
      <button type="button" className="back-link" onClick={() => navigate('/projects')}>
        <span className="back-link-arrow" aria-hidden="true">
          ←
        </span>
        返回项目列表
      </button>

      <div className="detail-head">
        <div>
          <div className="detail-title-row">
            <h1>{project.project_name}</h1>
            <StatusBadge status={project.status} />
            {verifyStarted && <VerifyBadge status={project.verify_status} />}
            {project.frontend_rce === 1 && (
              <span className="frontend-rce-badge" title="远程 HTTP 验证通过的 RCE（无权限或注册开放+普通用户）">
                前台 RCE
              </span>
            )}
            {project.project_kind && (
              <>
                <span
                  className="project-kind-badge"
                  title={`项目类型：${project.project_kind.kind_label}`}
                >
                  {project.project_kind.kind_label}
                </span>
                <span
                  className={
                    'project-web-badge' +
                    (project.project_kind.has_web === true
                      ? ' has-web'
                      : project.project_kind.has_web === false
                        ? ' no-web'
                        : ' pending-web')
                  }
                  title={
                    project.project_kind.has_web === true
                      ? '存在可部署/可访问的 Web 服务或站点入口'
                      : project.project_kind.has_web === false
                        ? '无典型 Web 站点入口（如纯 App/CLI/库）'
                        : '工作区尚未就绪，待审计开始后识别'
                  }
                >
                  {project.project_kind.web_label}
                </span>
              </>
            )}
            {(project.has_web === 1 || project.project_kind?.has_web === true) && (
              <span
                className={
                  'reg-badge' +
                  (project.has_registration === 1
                    ? ' reg-yes'
                    : project.has_registration === 0
                      ? ' reg-no'
                      : ' reg-pending')
                }
                title={
                  project.has_registration === 1
                    ? project.reg_default_open != null
                      ? `存在注册功能，默认${project.reg_default_open === 1 ? '开放' : '关闭'}注册`
                      : '存在注册功能'
                    : project.has_registration === 0
                      ? '未检测到用户注册功能'
                      : '注册功能尚未识别（等待语义判定 / 靶机搭建回填，或点击重新判定）'
                }
              >
                {project.has_registration === 1
                  ? '注册功能 有'
                  : project.has_registration === 0
                    ? '注册功能 无'
                    : '注册功能 待识别'}
                {project.has_registration === 1 && project.reg_default_open != null && (
                  <> · 默认{project.reg_default_open === 1 ? '开放' : '关闭'}</>
                )}
              </span>
            )}
            {!verifyStarted && project.env_status !== 'none' && (
              <span className={'env-badge env-' + project.env_status}>
                {envBadgeLabel(project.env_status)}
              </span>
            )}
          </div>
          <p className="muted">
            {project.source_type === 'github' ? '🔗 ' : '📦 '}
            {project.archive_name}
            {project.source_type === 'github' && project.source_version && (
              <span className="version-badge">{project.source_version}</span>
            )}
            {' · 创建于 '}
            {fmtTime(project.created_at)}
            {' · 代码审计耗时 '}
            <strong>{fmtDuration(project.audit_duration_ms)}</strong>
            {' · 远程验证耗时 '}
            <strong>{fmtDuration(project.verify_duration_ms)}</strong>
          </p>
        </div>
        <div className="detail-actions">
          {canPauseAudit && (
            <button
              className="btn btn-secondary"
              onClick={() => api.pause(project.id).then(reload)}
            >
              暂停审计
            </button>
          )}
          {canResumeAudit && (
            <button
              className="btn btn-secondary"
              onClick={() => api.resume(project.id).then(reload)}
            >
              继续审计
            </button>
          )}
          {verifyRunning ? (
            <button
              className="btn btn-secondary"
              onClick={() => api.pause(project.id).then(reload)}
            >
              暂停验证
            </button>
          ) : needsNextStep ? (
            <button
              className="btn btn-primary"
              title="代码审计已完成，选择下一步：进入靶机验证"
              onClick={() => setNextStepOpen(true)}
            >
              继续（选择下一步）
            </button>
          ) : (
            auditDone && (
              <button
                className="btn btn-primary"
                title={'搭建靶机并对全部中高危漏洞做远程实测'}
                onClick={() => onStartVerify()}
              >
                {verifyStarted ? '重跑远程验证' : '远程靶机验证'}
              </button>
            )
          )}
          <a
            className="btn btn-secondary"
            href={api.reportUrl(project.id)}
            target="_blank"
            rel="noreferrer"
          >
            预览报告
          </a>
          <a className="btn btn-secondary" href={api.reportUrl(project.id, true)}>
            导出报告
          </a>
        </div>
      </div>

      {project.error_message &&
        project.status !== 'running' &&
        project.status !== 'queued' && (
        <div className="error-banner">审计提示：{project.error_message}</div>
      )}
      {project.verify_error &&
        project.verify_status !== 'running' &&
        project.verify_status !== 'queued' && (
        <div className="error-banner">验证提示：{project.verify_error}</div>
      )}

      <section className="flow-section">
        <h3 className="section-title flow-title">
          <span>
            实时流程
            {envBuilding && (
              <span className="env-hint">
                {isHarnessVerify
                  ? '（沙箱验证环境搭建中…）'
                  : verifyStarted
                    ? '（等待靶机/沙箱环境就绪…）'
                    : '（靶机环境与代码审计并行搭建中…）'}
              </span>
            )}
          </span>
          <span className="flow-actions">
            <button className="btn btn-ghost btn-sm" onClick={onReaudit} disabled={auditRunning}>
              重新审计
            </button>
            <button className="btn btn-ghost btn-sm" onClick={onReprocess} disabled={auditRunning}>
              复用结果重跑(从去重开始)
            </button>
            <button
              className="btn btn-ghost btn-sm"
              onClick={() => onStartVerify()}
              disabled={!auditDone || verifyRunning}
              title={
                !auditDone
                  ? '需先完成代码审计'
                  : verifyRunning
                    ? '验证进行中'
                    : '对当前版本做远程实测'
              }
            >
              {verifyStarted ? '重跑验证' : '开始验证'}
            </button>
            {project.env_status === 'failed' && (
              <button
                className="btn btn-ghost btn-sm"
                onClick={onRetryEnv}
                disabled={verifyRunning}
                title={verifyRunning ? '验证进行中' : '重新排队靶机环境预搭建'}
              >
                重试环境搭建
              </button>
            )}
            {project.env_status !== 'none' && (
              <button
                className="btn btn-ghost btn-sm"
                onClick={onClearEnv}
                disabled={verifyRunning}
                title={verifyRunning ? '验证进行中，无法清除' : '验证完靶机默认只停止（便于二次验证），点此彻底清除'}
              >
                清除靶机
              </button>
            )}
          </span>
        </h3>
        <AgentFlow
          auditEvents={auditEvents}
          verifyEvents={verifyEvents}
          auditRunning={auditRunning}
          verifyRunning={verifyFlowRunning}
          auditDone={project.status === 'completed'}
          verifyDone={project.verify_status === 'completed'}
          envStatus={project.env_status}
          verifyStarted={remoteVerifyActive}
          verifyRuntime={clientVerifyRuntime}
          onRunStage={onRunStage}
          subagentCount={subagentCountForLanguage(project.audit_language || '')}
        />
      </section>

      <div className="detail-grid">
        <ResultsRenderBoundary
          dependencies={[
            vulnerabilityIndex,
            exploitDerived,
            auditRunning,
            verifyStarted,
            verifyRunning,
            historyEnabled,
            isHarnessVerify,
            project.verify_status,
            resultTab,
            expandedGroups,
            sevViewFilter,
            authSevFilter,
            id,
            onOpenVuln,
          ]}
          render={() => (
            <section className="results-section">
          <div className="results-tabs">
            <button
              className={'rtab' + (resultTab === 'all' ? ' active' : '')}
              onClick={() => setResultTab('all')}
            >
              总漏洞<span className="rtab-count">{vulns.length}</span>
            </button>
            <button
              className={'rtab' + (resultTab === 'single' ? ' active' : '')}
              onClick={() => setResultTab('single')}
            >
              远程成功·单个<span className="rtab-count">{successCount}</span>
            </button>
            <button
              className={'rtab' + (resultTab === 'single_fail' ? ' active' : '')}
              onClick={() => setResultTab('single_fail')}
            >
              远程验证·单个（未成功）
              <span className="rtab-count">{notSuccessCount}</span>
            </button>
            {historyEnabled && (
              <button
                className={'rtab' + (resultTab === 'single_hist' ? ' active' : '')}
                onClick={() => setResultTab('single_hist')}
              >
                远程验证·其他版本<span className="rtab-count">{singleHistSuccess.length}</span>
              </button>
            )}
            <button
              className={'rtab' + (resultTab === 'chain' ? ' active' : '')}
              onClick={() => setResultTab('chain')}
            >
              远程验证·组合<span className="rtab-count">{chainTotal}</span>
            </button>
            {historyEnabled && (
              <button
                className={'rtab' + (resultTab === 'chain_hist' ? ' active' : '')}
                onClick={() => setResultTab('chain_hist')}
              >
                组合验证·其他版本<span className="rtab-count">{chainHistSuccess.length}</span>
              </button>
            )}
          </div>

          {verifyStarted && chmCount > 0 && (
            <div className="verify-progress-strip" role="status">
              <span className="verify-progress-main">
                {isHarnessVerify ? '沙箱验证' : '严重/高危/中危'}{' '}
                <strong>{verifiedWithResult}/{chmCount}</strong> 已有结论
              </span>
              <span className="verify-progress-breakdown">
                远程成功 {successCount}
                {restrictedCount > 0 && <> · 受限 {restrictedCount}</>}
                {failedCount > 0 && <> · 失败 {failedCount}</>}
                {timeoutCount > 0 && <> · 超时受限 {timeoutCount}</>}
                {pendingCount > 0 && (
                  <span className="verify-progress-pending"> · 待验证 {pendingCount}</span>
                )}
              </span>
              {pendingCount > 0 && verifyRunning && (
                <span className="verify-progress-hint muted">验证进行中，待验证项会随子智能体落盘自动更新</span>
              )}
            </div>
          )}

          {chainPhaseActive && (
            <div className="verify-progress-strip verify-progress-strip-chain" role="status">
              <span className="verify-progress-main">
                组合利用链{' '}
                {chainTotal > 0 ? (
                  <>
                    <strong>{chainVerifiedCount}/{chainTotal}</strong> 已有结论
                  </>
                ) : (
                  <>验证进行中…</>
                )}
              </span>
              {chainTotal > 0 && (
                <span className="verify-progress-breakdown">
                  成功 {chainSuccessCount}
                  {chainRestrictedCount > 0 && <> · 受限 {chainRestrictedCount}</>}
                  {chainFailedOnlyCount > 0 && <> · 失败 {chainFailedOnlyCount}</>}
                  {chainPendingCount > 0 && (
                    <span className="verify-progress-pending">
                      {' '}
                      · {verifyRunning ? '验证中' : '未完成(待续跑)'} {chainPendingCount}
                    </span>
                  )}
                </span>
              )}
              <span className="verify-progress-hint muted">
                {verifyRunning
                  ? '组合链验证进行中，每完成一条链会在此实时更新（成功 / 受限 / 失败及说明）'
                  : chainPendingCount > 0
                    ? '验证被中断，仍有组合链未跑完（覆盖门禁未收尾）；点右上角「继续审计」续跑即可让其归入成功/受限/失败之一'
                    : '组合链结论已全部落盘'}
              </span>
            </div>
          )}

          <div className="results-body">
            {resultTab === 'all' &&
              (vulns.length === 0 ? (
                <div className="empty-block">
                  {auditRunning ? '审计进行中，漏洞将实时呈现…' : '未发现漏洞'}
                </div>
              ) : (
                <>
                  {/* 实战五级 + 总数：共 6 个计数（可点击按等级筛选下方漏洞列表） */}
                  <div className="realteam-strip">
                    {SEVERITY_ORDER.map((s) => (
                      <button
                        key={s}
                        type="button"
                        className={'rts-cell rts-' + s + (sevViewFilter === s ? ' active' : '')}
                        onClick={() => setSevViewFilter((cur) => (cur === s ? 'all' : s))}
                        title={`只看实战 ${REALTEAM_LABEL[s]} 的漏洞（再点一次取消）`}
                      >
                        <span className="rts-label">{REALTEAM_LABEL[s]}</span>
                        <span className="rts-num">{grouped[s].length}</span>
                      </button>
                    ))}
                    <button
                      type="button"
                      className={'rts-cell rts-total' + (sevViewFilter === 'all' ? ' active' : '')}
                      onClick={() => setSevViewFilter('all')}
                      title="显示全部漏洞"
                    >
                      <span className="rts-label">总漏洞</span>
                      <span className="rts-num">{vulns.length}</span>
                    </button>
                  </div>
                  <VirtualizedVulnerabilityList
                    index={vulnerabilityIndex}
                    severityFilter={sevViewFilter}
                    expandedGroups={expandedGroups}
                    onExpand={(severity) =>
                      setExpandedGroups((current) => ({ ...current, [severity]: true }))
                    }
                    onOpen={onOpenVuln}
                  />
                </>
              ))}

            {resultTab === 'single' &&
              (!verifyStarted ? (
                <div className="empty-block">完成审计后，点击右上角"开始漏洞验证"生成远程利用结果</div>
              ) : singleSuccess.length === 0 ? (
                <div className="empty-block">
                  {verifyRunning ? '验证进行中，远程利用成功的单个漏洞将在此呈现…' : '暂无远程验证成功的单个漏洞'}
                </div>
              ) : (
                <div className="exploit-col">
                  {(
                    [
                      {
                        key: 'none',
                        label: '无权限（前台可直接触发）',
                        items: singleSuccessByAuth.none,
                      },
                      {
                        key: 'user',
                        label: '低权限（普通用户 / 注册账号可触发）',
                        items: singleSuccessByAuth.user,
                      },
                      {
                        key: 'admin',
                        label: '管理员权限（需管理员/高权限账号）',
                        items: singleSuccessByAuth.admin,
                      },
                    ] as const
                  ).map((grp) => (
                    <details className="auth-group" key={grp.key} open>
                      <summary>
                        {grp.label}
                        <span className="rtab-count">{grp.items.length}</span>
                      </summary>
                      {grp.items.length === 0 ? (
                        <div className="empty-block">无</div>
                      ) : (
                        <>
                          {renderAuthSeverityStrip(
                            grp.items,
                            grp.key,
                            authSevFilter[grp.key],
                            (v) => setAuthSevFilter((cur) => ({ ...cur, [grp.key]: v }))
                          )}
                          {renderBySeverity(
                            grp.items,
                            grp.key,
                            historyEnabled,
                            authSevFilter[grp.key],
                            onOpenVuln
                          )}
                        </>
                      )}
                    </details>
                  ))}
                </div>
              ))}

            {resultTab === 'single_fail' &&
              (!verifyStarted ? (
                <div className="empty-block">完成审计后，点击右上角"开始漏洞验证"生成远程利用结果</div>
              ) : singleNotSuccess.length === 0 ? (
                <div className="empty-block">
                  {verifyRunning ? '验证进行中…' : '暂无未完全成功的单个漏洞'}
                </div>
              ) : (
                <div className="exploit-col">
                  <div className="chain-overview">
                    <p>
                      以下漏洞远程实测未完全成功，可按状态查看；点击漏洞打开详情。
                    </p>
                    <p className="verify-accounting">
                      对账：<strong>{verifiedWithResult}/{chmCount}</strong> 已有明确结论
                      {pendingCount > 0 ? (
                        <>，<strong className="verify-progress-pending">{pendingCount}</strong> 个待验证</>
                      ) : (
                        <>，单漏洞阶段已全部有结论</>
                      )}
                      {' '}（远程成功 {successCount} · 受限 {restrictedCount} · 失败 {failedCount}
                      {timeoutCount > 0 ? <> · 超时受限 {timeoutCount}</> : null}
                      {pendingCount > 0 ? <> · 待验证 {pendingCount}</> : null}）
                    </p>
                  </div>
                  {(
                    [
                      {
                        key: 'pending',
                        label: '待验证',
                        hint: '子智能体尚未产出结果，或验证仍在排队/进行中',
                        items: singlePendingWithVuln,
                        defaultOpen: verifyRunning,
                      },
                      {
                        key: 'restricted',
                        label: '受限',
                        hint: '代码链或部分条件已确认，但当前靶机/环境无法完全复现',
                        items: singleRestrictedWithVuln,
                        defaultOpen: true,
                      },
                      {
                        key: 'failed',
                        label: '失败',
                        hint: '远程实测未命中',
                        items: singleFailedWithVuln,
                        defaultOpen: true,
                      },
                    ] as const
                  ).map(({ key, label, hint, items, defaultOpen }) => {
                    if (items.length === 0) return null;
                    return (
                      <details key={key} className="auth-group" open={defaultOpen}>
                        <summary>
                          {label}
                          <span className="rtab-count">{items.length}</span>
                        </summary>
                        <p className="status-group-hint muted">{hint}</p>
                        <ExploitSeverityGroups
                          list={items}
                          keyPrefix={key}
                          showHistory={historyEnabled}
                          onOpen={onOpenVuln}
                          collapsible
                        />
                      </details>
                    );
                  })}
                </div>
              ))}

            {resultTab === 'single_hist' &&
              (!verifyStarted ? (
                <div className="empty-block">完成审计后，点击右上角"开始漏洞验证"生成历史版本验证结果</div>
              ) : singleHistSuccess.length === 0 ? (
                <div className="empty-block">
                  {verifyRunning
                    ? '验证进行中，可在历史版本打通的单个漏洞将在此呈现…'
                    : '暂无在其他历史版本验证成功的单个漏洞'}
                </div>
              ) : (
                <div className="exploit-col">
                  <div className="chain-overview">
                    以下单个漏洞虽在当前版本可能受限，但经 git 历史定位后，确认在历史版本可成功利用。
                  </div>
                  <VirtualExploitList
                    items={singleHistWithVuln}
                    historyOnly
                    onOpen={onOpenVuln}
                    listKey="single-history"
                  />
                </div>
              ))}

            {resultTab === 'chain' &&
              (!verifyStarted ? (
                <div className="empty-block">完成审计后，点击右上角"开始漏洞验证"生成组合利用链</div>
              ) : (
                <div className="exploit-col">
                  {(chainTotal > 0 || chainPhaseActive) && (
                    <div className="verify-progress-strip" role="status">
                      <span className="verify-progress-main">
                        {chainTotal > 0 ? (
                          <>
                            组合利用链 <strong>{chainVerifiedCount}/{chainTotal}</strong> 已有结论
                          </>
                        ) : (
                          <>组合链验证进行中，等待首条链落盘…</>
                        )}
                      </span>
                      {chainTotal > 0 && (
                        <span className="verify-progress-breakdown">
                          成功 {chainSuccessCount}
                          {chainRestrictedCount > 0 && <> · 受限 {chainRestrictedCount}</>}
                          {chainFailedOnlyCount > 0 && <> · 失败 {chainFailedOnlyCount}</>}
                          {chainPendingCount > 0 && (
                            <span className="verify-progress-pending">
                              {' '}
                              · {verifyRunning ? '验证中' : '未完成(待续跑)'} {chainPendingCount}
                            </span>
                          )}
                        </span>
                      )}
                      {verifyRunning ? (
                        <span className="verify-progress-hint muted">
                          每完成一条链会立即显示在下方（含失败/受限说明）
                        </span>
                      ) : (
                        chainPendingCount > 0 && (
                          <span className="verify-progress-hint muted">
                            验证被中断，下列链尚未跑完覆盖门禁；点右上角「继续审计」续跑即可让每条链归入 成功/受限/失败 之一
                          </span>
                        )
                      )}
                    </div>
                  )}
                  {parsedSummary.intro && chainTotal > 0 && (
                    <div className="chain-overview">{parsedSummary.intro}</div>
                  )}
                  {chainTotal === 0 && chainPhaseActive ? (
                    <div className="empty-block">主控正在构造并派发组合链子智能体，首条结果落盘后将在此呈现…</div>
                  ) : chainTotal === 0 ? (
                    <div className="empty-block">
                      {verifyRunning && pendingCount === 0
                        ? '单漏洞验证已完成，组合链验证进行中…'
                        : verifyRunning && pendingCount > 0
                          ? `单漏洞仍有 ${pendingCount} 个待验证，组合链将在全部完成后启动…`
                          : verifyRunning
                            ? '验证进行中，组合利用链将在此呈现…'
                            : '暂无组合利用链'}
                    </div>
                  ) : (
                    <>
                      <details className="auth-group" open>
                        <summary>
                          验证成功
                          <span className="rtab-count">{chainSuccessCount}</span>
                        </summary>
                        {chainSuccessList.length === 0 ? (
                          <div className="empty-block">
                            {verifyRunning && chainPendingCount > 0
                              ? '验证进行中，成功的组合链将在此呈现…'
                              : chainPendingCount > 0 &&
                                  (project.verify_status === 'failed' || project.verify_status === 'paused')
                                ? '验证已中断，组合链尚未完成；点右上角「继续审计」续跑'
                                : '暂无验证成功的组合链'}
                          </div>
                        ) : (
                          <VirtualChainList
                            items={chainSuccessList}
                            listKey="chain-success"
                            showHistory={historyEnabled}
                            remoteVerify
                          />
                        )}
                      </details>
                      {chainRestrictedCount > 0 && (
                        <details className="auth-group" open>
                          <summary>
                            验证受限
                            <span className="rtab-count">{chainRestrictedCount}</span>
                          </summary>
                          <VirtualChainList
                            items={chainRestrictedList}
                            listKey="chain-restricted"
                            showHistory={historyEnabled}
                            failed
                          />
                        </details>
                      )}
                      <details className="auth-group" open>
                        <summary>
                          验证失败
                          <span className="rtab-count">{chainFailedOnlyCount}</span>
                        </summary>
                        {chainFailedOnlyList.length === 0 ? (
                          <div className="empty-block">
                            {verifyRunning && chainPhaseActive
                              ? '其余链仍在验证中…'
                              : '暂无验证失败的组合链'}
                          </div>
                        ) : (
                          <VirtualChainList
                            items={chainFailedOnlyList}
                            listKey="chain-failed"
                            showHistory={historyEnabled}
                            failed
                          />
                        )}
                      </details>
                      {chainPendingCount > 0 && (
                        <details className="auth-group" open>
                          <summary>
                            {verifyRunning ? '待归类 / 验证中' : '未完成验证（待续跑）'}
                            <span className="rtab-count">{chainPendingCount}</span>
                          </summary>
                          <VirtualChainList
                            items={chainPendingList}
                            listKey="chain-pending"
                            showHistory={historyEnabled}
                            remoteVerify
                          />
                        </details>
                      )}
                    </>
                  )}
                </div>
              ))}

            {resultTab === 'chain_hist' &&
              (!verifyStarted ? (
                <div className="empty-block">完成审计后，点击右上角"开始漏洞验证"生成历史版本验证结果</div>
              ) : chainHistSuccess.length === 0 ? (
                <div className="empty-block">
                  {verifyRunning
                    ? '验证进行中，可在历史版本打通的组合链将在此呈现…'
                    : '暂无在其他历史版本验证成功的组合漏洞'}
                </div>
              ) : (
                <div className="exploit-col">
                  <div className="chain-overview">
                    以下组合利用链虽在当前版本可能受限，但经 git 历史定位后，确认在历史版本可成功利用。
                  </div>
                  <VirtualChainList
                    items={chainHistSuccess}
                    listKey="chain-history"
                    historyOnly
                  />
                </div>
              ))}
              </div>
            </section>
          )}
        />

        <section className="log-section">
          <div className="section-title-row">
            <h3 className="section-title">Pi 全过程日志</h3>
            <a
              className="btn btn-secondary btn-sm"
              href={api.projectEventArchiveUrl(project.id)}
              title="下载已归档的完整 gzip JSONL 日志；未归档项目会返回暂无归档"
            >
              下载完整日志归档
            </a>
          </div>
          <LogPanel events={events} liveText={liveText} />
        </section>
      </div>

      {activeVuln && (
        <VulnModal
          vuln={activeVuln}
          exploit={activeExploit}
          onClose={() => {
            setActiveVuln(null);
            setActiveExploit(null);
          }}
        />
      )}

      {nextStepOpen && (
        <NextStepModal
          project={project}
          onClose={() => setNextStepOpen(false)}
          onChoose={onChooseNextStep}
        />
      )}
    </div>
  );
}

const ResultsRenderBoundary = memo(
  function ResultsRenderBoundary({
    render,
  }: {
    dependencies: readonly unknown[];
    render: () => JSX.Element;
  }) {
    return render();
  },
  (previous, next) => {
    if (previous.dependencies.length !== next.dependencies.length) return false;
    return previous.dependencies.every((value, index) =>
      Object.is(value, next.dependencies[index])
    );
  }
);

function VirtualStack<T>({
  items,
  getKey,
  estimateSize,
  renderItem,
  maxHeight = 520,
  overscan = 8,
  className = '',
}: {
  items: readonly T[];
  getKey: (item: T, index: number) => string | number;
  estimateSize: (item: T, index: number) => number;
  renderItem: (item: T, index: number) => React.ReactNode;
  maxHeight?: number;
  overscan?: number;
  className?: string;
}) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => scrollRef.current,
    getItemKey: (itemIndex) => getKey(items[itemIndex], itemIndex),
    estimateSize: (itemIndex) => estimateSize(items[itemIndex], itemIndex),
    overscan,
  });
  if (items.length === 0) return null;

  const totalSize = virtualizer.getTotalSize();
  return (
    <div
      ref={scrollRef}
      className={`virtual-stack-scroll ${className}`.trim()}
      style={{ height: Math.min(Math.max(totalSize, 1), maxHeight) }}
    >
      <div className="virtual-stack-canvas" style={{ height: totalSize }}>
        {virtualizer.getVirtualItems().map((virtualItem) => (
          <div
            key={virtualItem.key}
            ref={virtualizer.measureElement}
            data-index={virtualItem.index}
            className="virtual-stack-row"
            style={{ transform: `translateY(${virtualItem.start}px)` }}
          >
            {renderItem(items[virtualItem.index], virtualItem.index)}
          </div>
        ))}
      </div>
    </div>
  );
}

type LogVirtualRow =
  | { kind: 'event'; key: string; event: AgentEvent }
  | { kind: 'live'; key: string; text: string }
  | { kind: 'notice'; key: string }
  | { kind: 'empty'; key: string };

const LogEventLine = memo(function LogEventLine({ event }: { event: AgentEvent }) {
  const meta = KIND_META[event.kind] || { label: event.kind, icon: '·' };
  return (
    <div className={`log-line kind-${event.kind}`}>
      <span className="log-icon">{meta.icon}</span>
      <div className="log-body">
        <span className="log-tag">
          {meta.label}
          {event.tool ? ` · ${event.tool}` : ''}
          {event.kind === 'agent_start' ? ` · ${event.agent}` : ''}
        </span>
        {event.text && <div className="log-text">{event.text}</div>}
      </div>
    </div>
  );
});

const LogPanel = memo(function LogPanel({
  events,
  liveText,
}: {
  events: AgentEvent[];
  liveText: string;
}) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const atBottomRef = useRef(true);
  const rows = useMemo<LogVirtualRow[]>(() => {
    const next: LogVirtualRow[] = [];
    if (events.length >= EVENT_FETCH_LIMIT) next.push({ kind: 'notice', key: 'fetch-limit' });
    for (let index = 0; index < events.length; index++) {
      const event = events[index];
      next.push({ kind: 'event', key: `event:${event.id}:${index}`, event });
    }
    if (liveText) next.push({ kind: 'live', key: 'live', text: liveText });
    if (next.length === 0) next.push({ kind: 'empty', key: 'empty' });
    return next;
  }, [events, liveText]);

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    getItemKey: (index) => rows[index].key,
    estimateSize: (index) => {
      const row = rows[index];
      if (row.kind === 'notice' || row.kind === 'empty') return 70;
      const textLength = row.kind === 'event' ? row.event.text?.length ?? 0 : row.text.length;
      return Math.min(260, 46 + Math.ceil(textLength / 80) * 20);
    },
    overscan: 12,
  });

  useEffect(() => {
    if (!atBottomRef.current || rows.length === 0) return;
    let secondFrame = 0;
    const firstFrame = requestAnimationFrame(() => {
      virtualizer.scrollToIndex(rows.length - 1, { align: 'end' });
      secondFrame = requestAnimationFrame(() => {
        const element = scrollRef.current;
        if (element && atBottomRef.current) element.scrollTop = element.scrollHeight;
      });
    });
    return () => {
      cancelAnimationFrame(firstFrame);
      if (secondFrame) cancelAnimationFrame(secondFrame);
    };
  }, [events.length, liveText, rows.length]);

  const onScroll = () => {
    const element = scrollRef.current;
    if (!element) return;
    atBottomRef.current =
      element.scrollHeight - element.scrollTop - element.clientHeight < 80;
  };

  return (
    <div className="log-stream" ref={scrollRef} onScroll={onScroll}>
      <div className="log-virtual-canvas" style={{ height: virtualizer.getTotalSize() }}>
        {virtualizer.getVirtualItems().map((virtualItem) => {
          const row = rows[virtualItem.index];
          return (
            <div
              key={virtualItem.key}
              ref={virtualizer.measureElement}
              data-index={virtualItem.index}
              className="log-virtual-row"
              style={{ transform: `translateY(${virtualItem.start}px)` }}
            >
              {row.kind === 'event' ? (
                <LogEventLine event={row.event} />
              ) : row.kind === 'live' ? (
                <div className="log-line kind-text live">
                  <span className="log-icon">✎</span>
                  <div className="log-body">
                    <span className="log-tag">输出中…</span>
                    <div className="log-text">{row.text}</div>
                  </div>
                </div>
              ) : row.kind === 'notice' ? (
                <div className="empty-block dark">
                  初始仅加载最近 {EVENT_FETCH_LIMIT} 条日志，更早记录见导出报告
                </div>
              ) : (
                <div className="empty-block dark">等待审计日志…</div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
});

const VulnerabilityItem = memo(function VulnerabilityItem({
  vuln,
  onOpen,
}: {
  vuln: Vulnerability;
  onOpen: (vuln: Vulnerability) => void;
}) {
  return (
    <div className="vuln-item" onClick={() => onOpen(vuln)} title="点击查看详情" role="button">
      <div className="vuln-item-main">
        <strong>{vuln.title}</strong>
        <span className="muted vuln-loc">
          {vuln.file_path}
          {vuln.line ? `:${vuln.line}` : ''}
        </span>
      </div>
      <div className="vuln-item-tags">
        {vuln.regrade_value && (
          <span className={'rtv-pill rtv-' + vuln.regrade_value}>
            实战 {vuln.regrade_value}
          </span>
        )}
        {vuln.auth_required && (
          <span
            className={'auth-pill auth-' + vuln.auth_required}
            title={vuln.auth_reason || AUTH_LABEL[vuln.auth_required]}
          >
            {AUTH_PILL_LABEL[vuln.auth_required]}
          </span>
        )}
        {vuln.severity_original && vuln.severity_original !== vuln.severity && (
          <span className="rtv-pill rtv-down" title="二次评级前等级">
            原 {SEVERITY_LABEL[vuln.severity_original]}
          </span>
        )}
        {vuln.category && <span className="vuln-cat">{vuln.category}</span>}
      </div>
    </div>
  );
});

type VulnerabilityVirtualRow =
  | { kind: 'group'; key: string; severity: Severity; count: number }
  | { kind: 'expand'; key: string; severity: Severity; hidden: number }
  | VulnerabilityDisplayRow;

const VirtualizedVulnerabilityList = memo(function VirtualizedVulnerabilityList({
  index,
  severityFilter,
  expandedGroups,
  onExpand,
  onOpen,
}: {
  index: VulnerabilityIndex;
  severityFilter: Severity | 'all';
  expandedGroups: Record<string, boolean>;
  onExpand: (severity: Severity) => void;
  onOpen: (vuln: Vulnerability) => void;
}) {
  const rows = useMemo<VulnerabilityVirtualRow[]>(() => {
    const next: VulnerabilityVirtualRow[] = [];
    for (const severity of SEVERITY_ORDER) {
      const vulnerabilities = index.bySeverity[severity];
      if (
        vulnerabilities.length === 0 ||
        (severityFilter !== 'all' && severityFilter !== severity)
      ) {
        continue;
      }
      next.push({
        kind: 'group',
        key: `group:${severity}`,
        severity,
        count: vulnerabilities.length,
      });
      const expanded = Boolean(expandedGroups[severity]);
      next.push(
        ...(expanded
          ? index.displayRows[severity].expanded
          : index.displayRows[severity].collapsed)
      );
      const hidden = expanded
        ? 0
        : Math.max(0, vulnerabilities.length - VULN_GROUP_CAP);
      if (hidden > 0) {
        next.push({
          kind: 'expand',
          key: `expand:${severity}`,
          severity,
          hidden,
        });
      }
    }
    return next;
  }, [expandedGroups, index, severityFilter]);

  return (
    <VirtualStack
      items={rows}
      getKey={(row) => row.key}
      estimateSize={(row) => {
        if (row.kind === 'group') return 42;
        if (row.kind === 'expand') return 48;
        if (row.kind === 'cluster') return 52 + row.faces.length * 76;
        return 76;
      }}
      maxHeight={520}
      overscan={10}
      className="results-virtual-list"
      renderItem={(row) => {
        if (row.kind === 'group') {
          return (
            <div className="vuln-group-head virtual-group-head">
              <span className={'badge sev-' + row.severity} title="实战等级">
                实战 {REALTEAM_LABEL[row.severity]}
              </span>
              <span className="muted">{row.count} 个</span>
            </div>
          );
        }
        if (row.kind === 'expand') {
          return (
            <button className="vuln-expand-btn" onClick={() => onExpand(row.severity)}>
              展开剩余 {row.hidden} 个
            </button>
          );
        }
        if (row.kind === 'cluster') {
          return (
            <div className="vuln-cluster">
              <div className="vuln-cluster-head">
                <span
                  className="vuln-cluster-badge"
                  title="同一代码点的多个利用面，各自独立验证"
                >
                  同点利用面
                </span>
                <span className="muted">1 个漏洞点 · {row.total} 个利用面</span>
              </div>
              {row.faces.map((vuln) => (
                <VulnerabilityItem
                  key={vuln.id}
                  vuln={vuln}
                  onOpen={onOpen}
                />
              ))}
            </div>
          );
        }
        return (
          <VulnerabilityItem
            vuln={row.vuln}
            onOpen={onOpen}
          />
        );
      }}
    />
  );
});

function normTitle(s: unknown): string {
  return String(s ?? '').replace(/\s+/g, '').toLowerCase();
}

function emptySeverityGroups(): Record<Severity, Vulnerability[]> {
  return { critical: [], high: [], medium: [], low: [], info: [] };
}

function buildVulnerabilityDisplayRows(
  list: Vulnerability[],
  clusterById: Map<string, Vulnerability[]>,
  severity: Severity
): VulnerabilityDisplayRow[] {
  const facesByCluster = new Map<string, Vulnerability[]>();
  for (const vuln of list) {
    if (!vuln.cluster_id) continue;
    const faces = facesByCluster.get(vuln.cluster_id);
    if (faces) faces.push(vuln);
    else facesByCluster.set(vuln.cluster_id, [vuln]);
  }

  const renderedClusters = new Set<string>();
  const rows: VulnerabilityDisplayRow[] = [];
  for (const vuln of list) {
    if (!vuln.cluster_id) {
      rows.push({ kind: 'item', key: `${severity}:v:${vuln.id}`, vuln });
      continue;
    }
    if (renderedClusters.has(vuln.cluster_id)) continue;
    renderedClusters.add(vuln.cluster_id);
    rows.push({
      kind: 'cluster',
      key: `${severity}:c:${vuln.cluster_id}`,
      clusterId: vuln.cluster_id,
      faces: facesByCluster.get(vuln.cluster_id) ?? [vuln],
      total: clusterById.get(vuln.cluster_id)?.length ?? 1,
    });
  }
  return rows;
}

function buildVulnerabilityIndex(vulns: Vulnerability[]): VulnerabilityIndex {
  const bySeverity = emptySeverityGroups();
  const chm: Vulnerability[] = [];
  const order = new Map<Vulnerability, number>();
  const exactTitle = new Map<string, Vulnerability>();
  const fullTitleByLength = new Map<number, Map<string, Vulnerability>>();
  const substringFirstByLength = new Map<number, Map<string, Vulnerability>>();
  const clusterById = new Map<string, Vulnerability[]>();

  for (let index = 0; index < vulns.length; index++) {
    const vuln = vulns[index];
    order.set(vuln, index);
    bySeverity[vuln.severity]?.push(vuln);
    if (vuln.severity === 'critical' || vuln.severity === 'high' || vuln.severity === 'medium') {
      chm.push(vuln);
    }
    if (vuln.cluster_id) {
      const cluster = clusterById.get(vuln.cluster_id);
      if (cluster) cluster.push(vuln);
      else clusterById.set(vuln.cluster_id, [vuln]);
    }

    const normalized = normTitle(vuln.title);
    if (!normalized) continue;
    if (!exactTitle.has(normalized)) exactTitle.set(normalized, vuln);

    let sameLength = fullTitleByLength.get(normalized.length);
    if (!sameLength) {
      sameLength = new Map();
      fullTitleByLength.set(normalized.length, sameLength);
    }
    if (!sameLength.has(normalized)) sameLength.set(normalized, vuln);

    // 旧匹配规则会用利用项标题的前 12 字符在漏洞标题中查找。
    // 把 1..12 长度的子串首命中项预建成索引，查询不再扫描全部漏洞。
    for (let length = 1; length <= Math.min(12, normalized.length); length++) {
      let substringMap = substringFirstByLength.get(length);
      if (!substringMap) {
        substringMap = new Map();
        substringFirstByLength.set(length, substringMap);
      }
      for (let start = 0; start + length <= normalized.length; start++) {
        const token = normalized.slice(start, start + length);
        if (!substringMap.has(token)) substringMap.set(token, vuln);
      }
    }
  }

  const displayRows = {} as VulnerabilityIndex['displayRows'];
  for (const severity of SEVERITY_ORDER) {
    const list = bySeverity[severity];
    const collapsedList =
      list.length > VULN_GROUP_CAP ? list.slice(0, VULN_GROUP_CAP) : list;
    const expanded = buildVulnerabilityDisplayRows(list, clusterById, severity);
    displayRows[severity] = {
      collapsed:
        collapsedList === list
          ? expanded
          : buildVulnerabilityDisplayRows(collapsedList, clusterById, severity),
      expanded,
    };
  }

  return {
    all: vulns,
    bySeverity,
    chm,
    order,
    exactTitle,
    fullTitleByLength,
    substringFirstByLength,
    titleLengths: [...fullTitleByLength.keys()].sort((a, b) => a - b),
    clusterById,
    displayRows,
  };
}

function findIndexedVulnerability(
  raw: unknown,
  index: VulnerabilityIndex
): Vulnerability | undefined {
  if (typeof raw === 'number' && Number.isFinite(raw)) return index.chm[raw - 1];

  const normalized = normTitle(raw);
  if (!normalized) return undefined;
  const exact = index.exactTitle.get(normalized);
  if (exact) return exact;

  let best: Vulnerability | undefined;
  let bestOrder = Number.POSITIVE_INFINITY;
  const consider = (candidate: Vulnerability | undefined) => {
    if (!candidate) return;
    const candidateOrder = index.order.get(candidate) ?? Number.POSITIVE_INFINITY;
    if (candidateOrder < bestOrder) {
      best = candidate;
      bestOrder = candidateOrder;
    }
  };

  const prefixLength = Math.min(normalized.length, 12);
  consider(
    index.substringFirstByLength
      .get(prefixLength)
      ?.get(normalized.slice(0, prefixLength))
  );

  // 保留旧规则中“利用项标题包含完整漏洞标题”的兼容匹配。
  // 查询只遍历标题字符串窗口与已有长度种类，不再遍历漏洞集合。
  for (const length of index.titleLengths) {
    if (length > normalized.length) break;
    const sameLength = index.fullTitleByLength.get(length);
    if (!sameLength) continue;
    for (let start = 0; start + length <= normalized.length; start++) {
      consider(sameLength.get(normalized.slice(start, start + length)));
      if (bestOrder === 0) return best;
    }
  }
  return best;
}

// 旧版验证结果只有一段 summary 文本，没有结构化 chains。
// 这里把 summary 里的 “利用链（A→B→C→D）：- A（…）：… - B（…）：…” 拆成结构化利用链，
// 让用户能逐跳看清、并明确哪条链已成功验证。

/** 远程验证 JSON 里部分条目会把数组字段写成字符串，直接 .some/.filter 会抛错白屏。 */
function asHistArray(v: unknown): HistoricalVersionResult[] {
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is HistoricalVersionResult => x != null && typeof x === 'object');
}

function asVersionArray(v: unknown): ExploitVersion[] {
  if (!Array.isArray(v)) return [];
  return v
    .map((item) => (typeof item === 'string' ? { version: item } : (item as ExploitVersion)))
    .filter((x) => String(x?.version ?? '').trim());
}

/** exploit_report 里 local_result/detail 等字段偶发为 JSON 对象，直接 JSX 渲染会白屏。 */
function formatExploitText(v: unknown): string {
  if (v == null) return '';
  if (typeof v === 'string') return v;
  if (typeof v === 'object') {
    try {
      return JSON.stringify(v, null, 2);
    } catch {
      return String(v);
    }
  }
  return String(v);
}

// 判定一条组合链是否符合「none/user → RCE」展示策略（见 lib/chainRceFilter.ts）

function parseSummaryChains(summary: string): { intro: string; chains: ExploitChain[] } {
  const empty = { intro: '', chains: [] as ExploitChain[] };
  if (!summary) return empty;

  const linkIdx = summary.indexOf('利用链');
  if (linkIdx === -1) return empty;
  const colonIdx = summary.indexOf('：', linkIdx);
  if (colonIdx === -1) return empty;

  // 链名起点：优先 ** 标记，否则回退到上一个句号/换行之后
  let headStart: number;
  const star = summary.lastIndexOf('**', linkIdx);
  if (star !== -1 && linkIdx - star < 40) {
    headStart = star + 2;
  } else {
    headStart =
      Math.max(summary.lastIndexOf('。', linkIdx), summary.lastIndexOf('\n', linkIdx)) + 1;
  }
  const name = summary.slice(headStart, colonIdx).replace(/\*\*/g, '').trim();
  const intro = summary.slice(0, headStart).replace(/\*\*/g, '').trim();

  // 跨版本 / 配置类描述视为链后的收尾说明
  const tailKeys = ['跨版本', '受影响版本', '调试信息泄露', '其中'];
  let tailIdx = -1;
  for (const k of tailKeys) {
    const i = summary.indexOf(k, colonIdx);
    if (i !== -1 && (tailIdx === -1 || i < tailIdx)) tailIdx = i;
  }
  const region = summary.slice(colonIdx + 1, tailIdx === -1 ? undefined : tailIdx);
  const tail = tailIdx === -1 ? '' : summary.slice(tailIdx).replace(/\*\*/g, '').trim();

  const steps: ChainStep[] = [];
  const stepRe = /[-–—•]\s*([A-Z])（([^）]+)）[：:]\s*([\s\S]*?)(?=\s*[-–—•]\s*[A-Z]（|$)/g;
  let m: RegExpExecArray | null;
  while ((m = stepRe.exec(region)) !== null) {
    steps.push({ vulnerability: `${m[1]} · ${m[2].trim()}`, description: m[3].trim() });
  }
  if (steps.length === 0) return { intro, chains: [] };

  const success = /成功验证|成功利用|被证实|已在本地/.test(summary);
  return {
    intro,
    chains: [
      {
        name: name || '核心利用链',
        status: success ? 'success' : 'unknown',
        impact: /RCE/i.test(region) ? 'RCE（远程代码执行）' : undefined,
        steps,
        detail: tail || undefined,
      },
    ],
  };
}

const EXPLOIT_LABEL: Record<string, { text: string; color: string }> = {
  success: { text: '远程利用成功', color: 'var(--error)' },
  failed: { text: '远程验证失败', color: 'var(--muted)' },
  restricted: { text: '源码确认 · 远程受限', color: 'var(--warning)' },
  unknown: { text: '待验证', color: 'var(--muted-soft)' },
};

const CHAIN_VERIFY_LABEL: Record<string, { text: string; color: string }> = {
  success: { text: '验证成功', color: 'var(--error)' },
  failed: { text: '验证失败', color: 'var(--muted)' },
  restricted: { text: '验证受限', color: 'var(--warning)' },
  // 覆盖门禁保证完成态无 unknown：仍为 unknown 只可能是验证进行中或被中断待续跑。
  unknown: { text: '待验证（未完成）', color: 'var(--muted-soft)' },
};

/** 从组合链 steps/detail 提取失败阻断步骤与原因说明。 */
function extractChainFailureInfo(chain: ExploitChain): { blockedStep?: string; reason: string } {
  const steps = normalizeChainSteps(chain.steps) ?? [];
  const failedStep = steps.find(
    (s) => s.result && !/success|通过|成功/i.test(String(s.result))
  );
  if (failedStep) {
    const label = [failedStep.vulnerability, failedStep.description].filter(Boolean).join(' — ');
    return {
      blockedStep: label || undefined,
      reason:
        formatExploitText(failedStep.evidence?.details) ||
        formatExploitText(chain.local_result) ||
        formatExploitText(chain.detail) ||
        '子智能体未返回详细失败原因',
    };
  }
  // detail/local_result 偶发为 JSON 对象；必须先转成字符串再 .match，否则会白屏。
  const detail =
    formatExploitText(chain.local_result) || formatExploitText(chain.detail) || '';
  const stepMatch = detail.match(/Step\s*(\d+)[^\n]*?(?:失败|阻断|未通过|无法|未完成|走不通)/i);
  if (stepMatch) {
    const stepN = parseInt(stepMatch[1], 10);
    const stepObj = steps[stepN - 1];
    return {
      blockedStep: stepObj
        ? [stepObj.vulnerability, stepObj.description].filter(Boolean).join(' — ')
        : `第 ${stepN} 步`,
      reason: detail || '验证在该步骤未能继续',
    };
  }
  const status = normalizeExploitStatus(chain.status);
  if (status === 'restricted') {
    const last = steps[steps.length - 1];
    return {
      blockedStep: last
        ? [last.vulnerability, last.description].filter(Boolean).join(' — ')
        : undefined,
      reason: detail || '链路上部分步骤已确认，但最终危害或 RCE 未能完全打通',
    };
  }
  return {
    blockedStep: steps.length > 0 ? steps[steps.length - 1].vulnerability : undefined,
    reason: detail || '远程实测未能走通整条利用链',
  };
}

/** 权威远程结论：权限矩阵优先；源码确认但没有动态入口不等于远程成功。 */
function remoteStatusOf(ex: ExploitItem): ExploitStatus {
  const cells = ex.privilege_results
    ? [ex.privilege_results.none, ex.privilege_results.user, ex.privilege_results.admin].filter(
        (cell) => cell && cell.status !== 'skipped'
      )
    : [];
  if (cells.length > 0) {
    if (cells.some((cell) => cell?.status === 'success')) return 'success';
    if (cells.some((cell) => cell?.status === 'restricted')) return 'restricted';
    if (cells.every((cell) => cell?.status === 'failed')) return 'failed';
    return 'unknown';
  }
  if (ex.remote_status) return normalizeExploitStatus(ex.remote_status);
  const local = normalizeExploitStatus(ex.local_exploitable);
  if (local !== 'success') return local;
  const evidence = `${formatExploitText(ex.local_result)} ${formatExploitText(ex.detail)}`;
  const codeOnly =
    /源码|代码(?:层|分析|确认)|无(?:路由|入口)|未暴露|code[-_\s]?(?:level|verified|confirmed|analysis)|not\s*triggerable|endpoint\s*not\s*exposed/i.test(
      evidence
    );
  const remoteProof =
    /(?:http|接口|端点|远程|靶机|请求|响应|回显|payload|poc|curl)[\s\S]{0,120}(?:成功|命中|触发|利用|200|201|302|回显)/i.test(
      evidence
    );
  return remoteProof && !codeOnly ? 'success' : 'restricted';
}

/** 与后端 normalizeExploitStatus 口径对齐，兼容历史非标准值。 */
function normalizeExploitStatus(raw: unknown): ExploitStatus {
  const s = String(raw ?? '')
    .toLowerCase()
    .trim();
  if (
    s === 'success' ||
    s === 'true' ||
    s === 'true_positive' ||
    s === 'verified_true_positive' ||
    s === 'hit' ||
    s === 'confirmed' ||
    s === 'verified' ||
    s === 'verified_rce' ||
    s === 'rce_confirmed' ||
    s === 'confirmed_with_evidence' ||
    s === 'exploited' ||
    s === 'exploitable' ||
    s === 'pwned'
  ) {
    return 'success';
  }
  if (
    s === 'restricted' ||
    s === 'conditional' ||
    s === 'partial' ||
    s === 'partially_verified' ||
    s === 'partially_exploitable' ||
    s === 'partial_success' ||
    s === 'limited' ||
    s === 'partially confirmed' ||
    s === 'partially verified' ||
    s === 'partially_confirmed' ||
    s === 'code-verified' ||
    s === 'verified_by_code_analysis' ||
    s === 'verified by code analysis' ||
    s === 'verified-nottriggerable' ||
    s === 'codeconfirmed_remoteendpointnotexposed' ||
    s === 'confirmed (code-level)'
  ) {
    return 'restricted';
  }
  if (
    s === 'failed' ||
    s === 'false' ||
    s === 'false_positive' ||
    s === 'falsepositive' ||
    s === 'fail' ||
    s === 'miss' ||
    s === 'blocked' ||
    s === 'not_exploitable' ||
    s === 'unexploitable'
  ) {
    return 'failed';
  }
  return 'unknown';
}

/** 把组合链 steps 归一成 {vulnerability,description,result}；字符串步骤落到 description。
 * 兼容远程验证产物的交替字段：name/status/detail/evidence(string)/success。 */
function normalizeChainSteps(raw: unknown): ChainStep[] | undefined {
  if (!Array.isArray(raw) || raw.length === 0) return undefined;
  const out: ChainStep[] = [];
  for (const item of raw) {
    if (item == null) continue;
    if (typeof item === 'string') {
      const description = item.trim();
      if (description) out.push({ description });
      continue;
    }
    if (typeof item !== 'object') continue;
    const step = item as Record<string, unknown>;
    const evidenceRaw = step.evidence;
    let evidenceDetails = '';
    let evidence: ChainStep['evidence'] | undefined;
    if (typeof evidenceRaw === 'string') {
      evidenceDetails = evidenceRaw.trim();
      if (evidenceDetails) evidence = { details: evidenceDetails };
    } else if (evidenceRaw && typeof evidenceRaw === 'object' && !Array.isArray(evidenceRaw)) {
      const er = evidenceRaw as { details?: unknown; url_accessed?: unknown; http_status?: unknown };
      evidenceDetails = formatExploitText(er.details).trim();
      evidence = {
        details: evidenceDetails || undefined,
        url_accessed: formatExploitText(er.url_accessed) || undefined,
        http_status: Number(er.http_status) || undefined,
      };
    }
    const vulnerability =
      formatExploitText(step.vulnerability).trim() ||
      formatExploitText(step.name).trim() ||
      undefined;
    const description =
      formatExploitText(step.description).trim() ||
      formatExploitText(step.detail).trim() ||
      evidenceDetails ||
      undefined;
    const result =
      formatExploitText(step.result).trim() ||
      formatExploitText(step.status).trim() ||
      (step.success === true ? 'success' : step.success === false ? 'failed' : '') ||
      undefined;
    if (!vulnerability && !description && !result) continue;
    out.push({
      vulnerability,
      description:
        description && description !== vulnerability
          ? description
          : !vulnerability
            ? description
            : undefined,
      result: result || undefined,
      evidence,
    });
  }
  return out.length ? out : undefined;
}

/** 展示前清洗组合链：对象型 detail、字符串 steps、非标准 status 一律归一，避免白屏。 */
function sanitizeChainForDisplay(chain: ExploitChain): ExploitChain {
  const raw = chain as ExploitChain & { chain_name?: string };
  const detail = formatExploitText(chain.detail).trim() || undefined;
  const local_result = formatExploitText(chain.local_result).trim() || undefined;
  const impact = formatExploitText(chain.impact).trim() || undefined;
  const name =
    formatExploitText(chain.name).trim() ||
    formatExploitText(raw.chain_name).trim() ||
    '未命名组合链';
  return {
    ...chain,
    name,
    impact,
    detail,
    local_result,
    status: normalizeExploitStatus(chain.status),
    steps: normalizeChainSteps(chain.steps),
  };
}

// 正向信号：文本明确提到"无需登录/账号/认证/权限即可触发"。
// 注意：不含"前台"——该词在中文审计报告里高度歧义（"前台文件/前台页面"常指前端页面，与"是否需要登录"无关），
// 曾导致大量误判，故从关键词表中移除。
const UNAUTH_HINT =
  /未授权|未认证|无需登录|无需认证|无需权限|无权限(?=(?:即可|就可|也能|仍可|直接))|匿名访问|匿名即可|游客(?:即可|可直接)?|无凭据|无需账号|pre-?auth|unauthenticated/i;

// 反向信号：文本明确提到"需要登录/账号/权限/认证"——真正执行过的验证过程一旦写明用了账号/登录，
// 就不能再判定为"无需授权"，该信号优先级高于上面的正向信号。
const AUTH_EVIDENCE =
  /需要?登录|已登录|登录后|登录态|需要?账号|使用[^。]{0,10}账号|以[^。]{0,10}身份登录|管理员(?:账号|身份|权限)|携带[^。]{0,12}(?:cookie|token|session)|需要?(?:权限|认证)|经过(?:身份验证|认证)/i;

// "无需登录/无需权限"等否定表达本身含有"登录/权限"字样，会误触发 AUTH_EVIDENCE，故先行掩蔽掉。
const UNAUTH_NEGATORS = /(?:无需|不需|免于?|不用|不必)(?:登录|认证|权限|账号|凭据)/g;

/**
 * 判断该漏洞/利用是否"无需授权即可触发"（前台/未授权）。
 * 优先采信 AI 在远程验证阶段显式给出的 auth_required 结构化判定（与验证过程强制保持一致，不再猜测）；
 * 仅当历史数据缺少该字段时，才退化为基于文本的兜底判断——且只看"本地验证/利用链细节"原文
 * （卡片上真实展示的验证记录），不采信漏洞审计阶段的泛化描述/评级理由，
 * 避免"审计侧泛泛提到无需登录、但实际验证过程写明需要登录"这类自相矛盾。
 */
function isUnauth(
  authRequired: AuthRequired | undefined,
  ...texts: (string | null | undefined)[]
): boolean {
  if (authRequired) return authRequired === 'none';
  const raw = texts.filter(Boolean).join(' ');
  if (!raw) return false;
  const masked = raw.replace(UNAUTH_NEGATORS, '');
  if (AUTH_EVIDENCE.test(masked)) return false;
  return UNAUTH_HINT.test(raw);
}

function isUnauthChain(c: ExploitChain): boolean {
  return isUnauth(
    c.auth_required,
    c.name,
    c.impact,
    c.detail,
    ...(c.steps ?? []).map((s) => `${s.vulnerability || ''} ${s.description || ''}`)
  );
}

const AUTH_LABEL: Record<string, string> = {
  none: '无需权限',
  user: '需登录（普通用户）',
  admin: '需管理员',
};

/** 权限降级矩阵展示的三档顺序与标签。 */
const PRIVILEGE_TIERS: { key: 'none' | 'user' | 'admin'; label: string }[] = [
  { key: 'none', label: '无权限' },
  { key: 'user', label: '低权限' },
  { key: 'admin', label: '管理员' },
];

/** 权限档位实测状态的展示样式。 */
const PRIV_STATUS_META: Record<string, { label: string; color: string }> = {
  success: { label: '成功', color: 'var(--error)' },
  restricted: { label: '受限', color: 'var(--warning)' },
  failed: { label: '失败', color: 'var(--muted)' },
  skipped: { label: '未测', color: 'var(--muted-soft)' },
  unknown: { label: '未知', color: 'var(--muted-soft)' },
};

/** 总漏洞列表用的精简鉴权标签（图二位置的 pill）。 */
const AUTH_PILL_LABEL: Record<string, string> = {
  none: '无需登录',
  user: '需登录',
  admin: '需管理员',
};

function ExploitCard({
  ex,
  vuln,
  historyOnly,
  onOpen,
}: {
  ex: ExploitItem;
  vuln?: Vulnerability;
  historyOnly?: boolean;
  onOpen?: (vuln: Vulnerability, exploit?: ExploitItem) => void;
}) {
  const remoteStatus = remoteStatusOf(ex);
  const status = historyOnly
    ? { text: '历史版本可利用', color: 'var(--error)' }
    : EXPLOIT_LABEL[remoteStatus] || EXPLOIT_LABEL.unknown;
  const title = vuln?.title ?? formatExploitText(ex.vulnerability);
  const unauth =
    remoteStatus === 'success' &&
    isUnauth(
      ex.auth_required,
      formatExploitText(ex.local_result),
      formatExploitText(ex.detail),
      title
    );
  const loc = vuln ? `${vuln.file_path}${vuln.line ? ':' + vuln.line : ''}` : '';
  const authKey = String(ex.auth_required ?? '');
  const clickable = Boolean(vuln && onOpen);
  return (
    <div
      className={'exploit-card' + (clickable ? ' exploit-card-clickable' : '')}
      onClick={clickable ? () => onOpen!(vuln!, ex) : undefined}
      title={clickable ? '点击查看详情' : undefined}
      role={clickable ? 'button' : undefined}
    >
      <div className="exploit-head">
        {unauth && (
          <span className="unauth-badge" title="无需任何权限/登录即可触发（前台/未授权）">
            ⚠ 无需授权
          </span>
        )}
        {vuln && <SeverityBadge severity={vuln.severity} />}
        {vuln?.regrade_value && <RedTeamValueBadge value={vuln.regrade_value} />}
        <span className="exploit-badge" style={{ background: status.color }}>
          {status.text}
        </span>
        <strong className="exploit-title">{title}</strong>
      </div>
      <div className="exploit-meta">
        {AUTH_LABEL[authKey] && (
          <span
            className="exploit-meta-pill"
            title={
              remoteStatus === 'success'
                ? '远程成功利用所需的最低权限'
                : '审计/验证声明的目标权限；当前远程验证未成功'
            }
          >
            {remoteStatus === 'success' ? '最低成功权限' : '权限线索'}：{AUTH_LABEL[authKey]}
          </span>
        )}
        {vuln?.category && <span className="exploit-meta-pill">{vuln.category}</span>}
        {loc && (
          <span className="exploit-meta-loc" title={loc}>
            {loc}
          </span>
        )}
      </div>
      {ex.privilege_results && (
        <div className="exploit-priv-matrix" title="权限降级测试：各权限档位下的实测结果">
          {PRIVILEGE_TIERS.map((tier) => {
            const cell = ex.privilege_results?.[tier.key];
            const st = cell?.status ?? 'skipped';
            const meta = PRIV_STATUS_META[st] || PRIV_STATUS_META.unknown;
            return (
              <span
                key={tier.key}
                className="priv-cell"
                title={cell?.evidence || `${tier.label}：${meta.label}`}
              >
                <span className="priv-tier">{tier.label}</span>
                <span className="priv-dot" style={{ background: meta.color }} />
                <span className="priv-status" style={{ color: meta.color }}>
                  {meta.label}
                </span>
              </span>
            );
          })}
        </div>
      )}
      {ex.impacts && ex.impacts.length > 0 && (
        <div className="exploit-impacts" title="该漏洞成功后可造成的多种危害/能力">
          {ex.impacts.map((imp, i) => (
            <span className="impact-pill" key={i}>
              {imp}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

const CHM_LEVELS = ['critical', 'high', 'medium'] as const;
type ChmLevel = (typeof CHM_LEVELS)[number];

function estimateExploitHeight({ ex, vuln }: ExploitWithVuln): number {
  const impactRows = Math.ceil((ex.impacts?.length ?? 0) / 3);
  const locLen = (vuln?.file_path?.length ?? 0) + String(vuln?.line ?? '').length;
  return Math.min(280, 118 + impactRows * 28 + (locLen > 48 ? 18 : 0) + (ex.privilege_results ? 36 : 0));
}

const VirtualExploitList = memo(function VirtualExploitList({
  items,
  listKey,
  historyOnly,
  onOpen,
  maxHeight = 420,
}: {
  items: readonly ExploitWithVuln[];
  listKey: string;
  historyOnly?: boolean;
  onOpen?: (vuln: Vulnerability, exploit?: ExploitItem) => void;
  maxHeight?: number;
}) {
  return (
    <VirtualStack
      items={items}
      getKey={({ ex, vuln }, index) =>
        `${listKey}:${normTitle(vuln?.title ?? ex.vulnerability)}:${index}`
      }
      estimateSize={estimateExploitHeight}
      maxHeight={maxHeight}
      overscan={5}
      className="exploit-virtual-list"
      renderItem={({ ex, vuln }) => (
        <ExploitCard
          ex={ex}
          vuln={vuln}
          historyOnly={historyOnly}
          onOpen={onOpen}
        />
      )}
    />
  );
});

const ExploitSeverityGroups = memo(function ExploitSeverityGroups({
  list,
  keyPrefix,
  severityFilter = 'all',
  onOpen,
  collapsible = false,
}: {
  list: readonly ExploitWithVuln[];
  keyPrefix: string;
  showHistory?: boolean;
  severityFilter?: Severity | 'all';
  onOpen?: (vuln: Vulnerability, exploit?: ExploitItem) => void;
  collapsible?: boolean;
}) {
  const { bySeverity, unmatched } = useMemo(() => {
    const grouped: Record<Severity, ExploitWithVuln[]> = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      info: [],
    };
    const missing: ExploitWithVuln[] = [];
    for (const item of list) {
      if (item.vuln) grouped[item.vuln.severity].push(item);
      else missing.push(item);
    }
    return { bySeverity: grouped, unmatched: missing };
  }, [list]);

  if (collapsible) {
    return (
      <>
        {SEVERITY_ORDER.map((severity) => {
          const items =
            severity === 'info' && unmatched.length > 0
              ? [...bySeverity.info, ...unmatched]
              : bySeverity[severity];
          if (items.length === 0) return null;
          return (
            <details key={severity} className="auth-subgroup" open>
              <summary>
                实战 {REALTEAM_LABEL[severity]}
                <span className="rtab-count">{items.length}</span>
              </summary>
              <VirtualExploitList
                items={items}
                listKey={`${keyPrefix}:${severity}`}
                onOpen={onOpen}
                maxHeight={360}
              />
            </details>
          );
        })}
      </>
    );
  }

  const visibleLevels =
    severityFilter === 'all'
      ? CHM_LEVELS
      : CHM_LEVELS.filter((severity) => severity === severityFilter);
  return (
    <>
      {visibleLevels.map((severity) => {
        const items = bySeverity[severity];
        if (items.length === 0) return null;
        return (
          <div key={severity} className="auth-sub">
            <div className="auth-sub-head">
              <span className={'badge sev-' + severity}>
                实战 {REALTEAM_LABEL[severity]}
              </span>
              <span className="muted">{items.length} 个</span>
            </div>
            <VirtualExploitList
              items={items}
              listKey={`${keyPrefix}:${severity}`}
              onOpen={onOpen}
            />
          </div>
        );
      })}
      {unmatched.length > 0 && (
        <div className="auth-sub">
          <div className="auth-sub-head">
            <span className="muted">未匹配到漏洞（{unmatched.length}）</span>
          </div>
          <VirtualExploitList
            items={unmatched}
            listKey={`${keyPrefix}:unmatched`}
            onOpen={onOpen}
          />
        </div>
      )}
    </>
  );
});

function estimateChainHeight(chain: ExploitChain): number {
  const textLength =
    formatExploitText(chain.detail).length + formatExploitText(chain.local_result).length;
  const historyRows =
    asVersionArray(chain.exploitable_versions).length +
    asHistArray(chain.historical_verification).length;
  return Math.min(
    900,
    150 + (chain.steps?.length ?? 0) * 58 + Math.ceil(textLength / 72) * 18 + historyRows * 58
  );
}

const VirtualChainList = memo(function VirtualChainList({
  items,
  listKey,
  historyOnly,
  showHistory = true,
  remoteVerify,
  failed,
  maxHeight = 440,
}: {
  items: readonly ExploitChain[];
  listKey: string;
  historyOnly?: boolean;
  showHistory?: boolean;
  remoteVerify?: boolean;
  failed?: boolean;
  maxHeight?: number;
}) {
  return (
    <VirtualStack
      items={items}
      getKey={(chain, index) => `${listKey}:${normTitle(chain.name)}:${index}`}
      estimateSize={estimateChainHeight}
      maxHeight={maxHeight}
      overscan={4}
      className="exploit-virtual-list chain-virtual-list"
      renderItem={(chain) =>
        failed ? (
          <ChainFailCard chain={chain} showHistory={showHistory} />
        ) : (
          <ChainCard
            chain={chain}
            historyOnly={historyOnly}
            showHistory={showHistory}
            remoteVerify={remoteVerify}
          />
        )
      }
    />
  );
});

function countChmBySeverity(list: { ex: ExploitItem; vuln?: Vulnerability }[]) {
  const counts: Record<ChmLevel, number> = {
    critical: 0,
    high: 0,
    medium: 0,
  };
  for (const { vuln } of list) {
    const s = vuln?.severity;
    if (s === 'critical' || s === 'high' || s === 'medium') counts[s]++;
  }
  return counts;
}

/** 权限分组标题下方的严重/高危/中危筛选条（可点击切换，显示各等级数量）。 */
function renderAuthSeverityStrip(
  list: { ex: ExploitItem; vuln?: Vulnerability }[],
  _groupKey: string,
  filter: Severity | 'all',
  onFilter: (v: Severity | 'all') => void
) {
  const counts = countChmBySeverity(list);
  return (
    <div className="realteam-strip auth-sev-strip">
      {CHM_LEVELS.map((s) => (
        <button
          key={s}
          type="button"
          className={
            'rts-cell rts-' +
            s +
            (filter === s ? ' active' : '') +
            (counts[s] === 0 ? ' rts-empty' : '')
          }
          disabled={counts[s] === 0}
          onClick={() => onFilter(filter === s ? 'all' : s)}
          title={`只看实战 ${REALTEAM_LABEL[s]}（再点一次取消）`}
        >
          <span className="rts-label">{REALTEAM_LABEL[s]}</span>
          <span className="rts-num">{counts[s]}</span>
        </button>
      ))}
      <button
        type="button"
        className={'rts-cell rts-total' + (filter === 'all' ? ' active' : '')}
        onClick={() => onFilter('all')}
        title="显示该分组全部漏洞"
      >
        <span className="rts-label">合计</span>
        <span className="rts-num">{list.length}</span>
      </button>
    </div>
  );
}

/** 把一组（已过滤为 严重/高危/中危 的）利用项按实战等级再分小组渲染（点2）。 */
function renderBySeverity(
  list: { ex: ExploitItem; vuln?: Vulnerability }[],
  keyPrefix: string,
  showHistory: boolean,
  sevFilter: Severity | 'all' = 'all',
  onOpen?: (vuln: Vulnerability, exploit?: ExploitItem) => void
) {
  return (
    <ExploitSeverityGroups
      list={list}
      keyPrefix={keyPrefix}
      showHistory={showHistory}
      severityFilter={sevFilter}
      onOpen={onOpen}
    />
  );
}

function ChainCard({
  chain,
  historyOnly,
  showHistory = true,
  remoteVerify = false,
}: {
  chain: ExploitChain;
  historyOnly?: boolean;
  showHistory?: boolean;
  remoteVerify?: boolean;
}) {
  const status = historyOnly
    ? { text: '历史版本可利用', color: 'var(--error)' }
    : remoteVerify
      ? CHAIN_VERIFY_LABEL[normalizeExploitStatus(chain.status)] || CHAIN_VERIFY_LABEL.unknown
      : EXPLOIT_LABEL[normalizeExploitStatus(chain.status)] || EXPLOIT_LABEL.unknown;
  const unauth = isUnauth(
    chain.auth_required,
    chain.name,
    chain.impact,
    chain.detail,
    ...(chain.steps ?? []).map((s) => `${s.vulnerability || ''} ${s.description || ''}`)
  );
  return (
    <div className="exploit-card chain-card">
      <div className="exploit-head">
        {unauth && (
          <span className="unauth-badge" title="无需任何权限/登录即可触发（前台/未授权）">
            ⚠ 无需授权
          </span>
        )}
        <span className="exploit-badge" style={{ background: status.color }}>
          {status.text}
        </span>
        <strong className="exploit-title">{chain.name}</strong>
      </div>
      {chain.impact && (
        <div className="chain-impact">
          最终危害：<strong>{chain.impact}</strong>
        </div>
      )}
      {chain.steps && chain.steps.length > 0 && (
        <div className="exploit-block">
          <h4>利用链步骤</h4>
          <ol className="chain-steps">
            {chain.steps.map((s, i) => (
              <li key={i}>
                {s.vulnerability && <span className="chain-step-vuln">{s.vulnerability}</span>}
                {s.description && <span className="chain-step-desc">{s.description}</span>}
              </li>
            ))}
          </ol>
        </div>
      )}
      {chain.detail && (
        <div className="exploit-block">
          <h4>技术细节</h4>
          <p>{formatExploitText(chain.detail)}</p>
        </div>
      )}
      {showHistory &&
        (() => {
          const versions = asVersionArray(chain.exploitable_versions);
          if (versions.length === 0) return null;
          return (
            <div className="exploit-block">
              <h4>可成功利用的历史版本</h4>
              <div className="version-list">
                {versions.map((v, i) => (
                  <div key={i} className="version-row">
                    <span className="version-tag">{v.version}</span>
                    {v.github_url && (
                      <a href={v.github_url} target="_blank" rel="noreferrer" className="version-url">
                        {v.github_url}
                      </a>
                    )}
                    {v.note && <span className="version-note muted">{v.note}</span>}
                  </div>
                ))}
              </div>
            </div>
          );
        })()}
      {showHistory && <HistoricalBlock items={asHistArray(chain.historical_verification)} />}
    </div>
  );
}

function ChainFailCard({ chain, showHistory = true }: { chain: ExploitChain; showHistory?: boolean }) {
  const statusNorm = normalizeExploitStatus(chain.status);
  const status = CHAIN_VERIFY_LABEL[statusNorm] || CHAIN_VERIFY_LABEL.failed;
  const { blockedStep, reason } = extractChainFailureInfo(chain);
  const unauth = isUnauth(
    chain.auth_required,
    chain.name,
    chain.impact,
    chain.detail,
    ...(chain.steps ?? []).map((s) => `${s.vulnerability || ''} ${s.description || ''}`)
  );
  return (
    <div className="exploit-card chain-card chain-fail-card">
      <div className="exploit-head">
        {unauth && (
          <span className="unauth-badge" title="链起点无需任何权限/登录">
            ⚠ 无需授权
          </span>
        )}
        <span className="exploit-badge" style={{ background: status.color }}>
          {status.text}
        </span>
        <strong className="exploit-title">{chain.name}</strong>
      </div>
      {chain.impact && (
        <div className="chain-impact">
          目标危害：<strong>{chain.impact}</strong>
        </div>
      )}
      {blockedStep && (
        <div className="exploit-block chain-fail-block">
          <h4>阻断步骤</h4>
          <p className="chain-fail-step">{blockedStep}</p>
        </div>
      )}
      <div className="exploit-block chain-fail-block">
        <h4>失败原因</h4>
        <p>{formatExploitText(reason)}</p>
      </div>
      {chain.steps && chain.steps.length > 0 && (
        <div className="exploit-block">
          <h4>利用链步骤</h4>
          <ol className="chain-steps">
            {chain.steps.map((s, i) => {
              const stepFailed = s.result && !/success|通过|成功/i.test(s.result);
              return (
                <li key={i} className={stepFailed ? 'chain-step-failed' : undefined}>
                  {s.vulnerability && <span className="chain-step-vuln">{s.vulnerability}</span>}
                  {s.description && <span className="chain-step-desc">{s.description}</span>}
                  {s.result && (
                    <span className={'chain-step-result' + (stepFailed ? ' failed' : '')}>
                      {formatExploitText(s.result)}
                    </span>
                  )}
                </li>
              );
            })}
          </ol>
        </div>
      )}
      {showHistory &&
        (() => {
          const versions = asVersionArray(chain.exploitable_versions);
          if (versions.length === 0) return null;
          return (
            <div className="exploit-block">
              <h4>相关历史版本</h4>
              <div className="version-list">
                {versions.map((v, i) => (
                  <div key={i} className="version-row">
                    <span className="version-tag">{v.version}</span>
                    {v.github_url && (
                      <a href={v.github_url} target="_blank" rel="noreferrer" className="version-url">
                        {v.github_url}
                      </a>
                    )}
                    {v.note && <span className="version-note muted">{v.note}</span>}
                  </div>
                ))}
              </div>
            </div>
          );
        })()}
      {showHistory && <HistoricalBlock items={asHistArray(chain.historical_verification)} />}
    </div>
  );
}

const HIST_METHOD_LABEL: Record<string, string> = {
  git_analysis: '代码差异分析',
  live_target: '实测靶机',
};

/** 历史版本验证结果展示（单漏洞与组合链共用）。 */
function HistoricalBlock({ items }: { items?: unknown }) {
  const list = asHistArray(items);
  if (list.length === 0) return null;
  return (
    <div className="exploit-block">
      <h4>历史版本验证</h4>
      <div className="version-list">
        {list.map((h, i) => {
          const st = EXPLOIT_LABEL[h.status || 'unknown'] || EXPLOIT_LABEL.unknown;
          return (
            <div key={i} className="hist-row">
              <div className="hist-row-head">
                <span className="version-tag">{h.version}</span>
                <span className="hist-status" style={{ color: st.color }}>
                  {st.text}
                </span>
                {h.method && (
                  <span className="hist-method">{HIST_METHOD_LABEL[h.method] || h.method}</span>
                )}
              </div>
              {h.github_url && (
                <a href={h.github_url} target="_blank" rel="noreferrer" className="version-url">
                  {h.github_url}
                </a>
              )}
              {h.fix_commit && <div className="hist-meta muted">修复/防御提交：{h.fix_commit}</div>}
              {formatExploitText(h.reason || (h as { analysis?: string }).analysis) && (
                <div className="hist-reason">
                  {formatExploitText(h.reason || (h as { analysis?: string }).analysis)}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function VulnModal({
  vuln,
  exploit,
  onClose,
}: {
  vuln: Vulnerability;
  exploit?: ExploitItem | null;
  onClose: () => void;
}) {
  const versions = exploit ? asVersionArray(exploit.exploitable_versions) : [];
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
        {exploit?.local_result && (
          <div className="modal-block">
            <h4>验证过程与证据</h4>
            <p>{formatExploitText(exploit.local_result)}</p>
          </div>
        )}
        {exploit?.detail && (
          <div className="modal-block">
            <h4>利用链细节</h4>
            <p>{formatExploitText(exploit.detail)}</p>
          </div>
        )}
        {versions.length > 0 && (
          <div className="modal-block">
            <h4>可成功利用的历史版本</h4>
            <div className="version-list">
              {versions.map((v, i) => (
                <div key={i} className="version-row">
                  <span className="version-tag">{v.version}</span>
                  {v.github_url && (
                    <a href={v.github_url} target="_blank" rel="noreferrer" className="version-url">
                      {v.github_url}
                    </a>
                  )}
                  {v.note && <span className="version-note muted">{v.note}</span>}
                </div>
              ))}
            </div>
          </div>
        )}
        {exploit && <HistoricalBlock items={exploit.historical_verification} />}
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
