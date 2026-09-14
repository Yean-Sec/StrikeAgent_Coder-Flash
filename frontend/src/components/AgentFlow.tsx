import { useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { animate } from 'animejs';
import type { AgentEvent } from '../lib/types';
import './AgentFlow.css';

interface Props {
  auditEvents: AgentEvent[];
  verifyEvents: AgentEvent[];
  auditRunning: boolean;
  verifyRunning: boolean;
  auditDone: boolean;
  verifyDone: boolean;
  /** 并行靶机环境预搭建状态（none/building/ready/failed）。 */
  envStatus?: string;
  /** 远程验证是否已开始（verify_status=running/completed）。 */
  verifyStarted?: boolean;
  /** 远程验证形态（full / none）。历史 mini 按完整靶机展示。 */
  verifyRuntime?: string;
  onRunStage?: (stage: string, mode: 'only' | 'from', opts?: { verify_history?: boolean }) => void;
  /** 所选语言的专项子智能体路数（最多 4 路，CWE 面合并）。 */
  subagentCount?: number;
}

const AUDIT_STAGES = [
  { stage: 'subagent', label: '多智能体审计' },
  { stage: 'dedup', label: 'AI 智能去重' },
  { stage: 'codeverify', label: '代码级验证' },
  { stage: 'regrade', label: '红队二次评级' },
];
const VERIFY_STAGES = [
  { stage: 'env', label: '靶机环境搭建' },
  { stage: 'remote', label: '远程验证' },
  { stage: 'chain', label: '组合验证' },
];
const ONLY_OK = new Set(['env']);
/** 「继续审计 / 复用结果 / 分环节」会新开一轮；进度只看这一轮，避免旧「▶ 红队二次评级」把当前步钉死。 */
const AUDIT_ROUND_MARKS = ['▶ 续跑代码审计', '♻ 复用已有子智能体', '▶ 分环节运行'];

function eventsAfterLatestRound(list: AgentEvent[]): AgentEvent[] {
  let idx = 0;
  for (let i = 0; i < list.length; i++) {
    const e = list[i];
    if (e.kind === 'system' && e.text && AUDIT_ROUND_MARKS.some((m) => e.text.includes(m))) idx = i;
  }
  return list.slice(idx);
}

type NodeStatus = 'done' | 'active' | 'pending' | 'skipped';
type Lane = 'audit' | 'verify';

const TOOL_LABEL: Record<string, string> = {
  Read: '读取文件',
  Grep: '检索代码',
  Glob: '匹配文件',
  Bash: '执行命令',
  Task: '派发子智能体',
  Agent: '派发子智能体',
  Skill: '启动技能',
  WebSearch: '联网搜索',
  WebFetch: '抓取网页',
  Write: '写入',
  Edit: '编辑',
};

interface NodeDef {
  id: string;
  label: string;
  icon: string;
  x: number;
  y: number;
  order: number;
  lane: Lane;
  kind: 'orchestrator' | 'subagent' | 'result';
}
interface EdgeDef {
  d: string;
  lane: Lane | 'bridge';
  targetOrder: number;
  fromId: string;
  toId: string;
  from: { x: number; y: number };
  to: { x: number; y: number };
  label?: { text: string; x: number; y: number; w?: number };
}
interface Layout {
  viewW: number;
  viewH: number;
  nodes: NodeDef[];
  edges: EdgeDef[];
  auditSteps: string[];
  verifySteps: string[];
}

const NODE_W = 146;
const NODE_H = 64;
const MIN_GAP = 88;
const MAX_GAP = 156;
const LANE_X = 92;
const PAD_Y = 28;
const ROW_GAP = 148;
const PAD_RIGHT = 20;
const AUDIT_COLS = 6;

function hEdge(from: NodeDef, to: NodeDef): { d: string; from: { x: number; y: number }; to: { x: number; y: number } } {
  const y = from.y + NODE_H / 2;
  const x1 = from.x + NODE_W;
  const x2 = to.x;
  const dx = x2 - x1;
  return {
    d: `M${x1},${y} C${x1 + dx * 0.42},${y} ${x2 - dx * 0.42},${y} ${x2},${y}`,
    from: { x: x1, y },
    to: { x: x2, y },
  };
}

function bridgePath(from: NodeDef, to: NodeDef): {
  d: string;
  from: { x: number; y: number };
  to: { x: number; y: number };
  mid: { x: number; y: number };
} {
  const x1 = from.x + NODE_W / 2;
  const y1 = from.y + NODE_H;
  const x2 = to.x + NODE_W / 2;
  const y2 = to.y;
  const midY = Math.round((y1 + y2) / 2);
  return {
    d: `M${x1},${y1} C${x1},${midY} ${x2},${midY} ${x2},${y2}`,
    from: { x: x1, y: y1 },
    to: { x: x2, y: y2 },
    mid: { x: Math.round((x1 + x2) / 2), y: midY },
  };
}

function colX(i: number, gap: number): number {
  return LANE_X + i * (NODE_W + gap);
}

function makeLayout(gap: number): Layout {
  const yAudit = PAD_Y;
  const yVerify = PAD_Y + NODE_H + ROW_GAP;
  const auditSpecs: Omit<NodeDef, 'x' | 'y'>[] = [
    { id: 'audit-orch', label: '主智能体调度', icon: '✦', order: 0, lane: 'audit', kind: 'orchestrator' },
    { id: 'audit', label: '多智能体审计', icon: '⦿', order: 1, lane: 'audit', kind: 'subagent' },
    { id: 'dedup', label: 'AI 智能去重', icon: '⧓', order: 2, lane: 'audit', kind: 'subagent' },
    { id: 'codeverify', label: '代码级验证', icon: '⦿', order: 3, lane: 'audit', kind: 'subagent' },
    { id: 'regrade', label: '红队二次评级', icon: '⚖', order: 4, lane: 'audit', kind: 'subagent' },
    { id: 'audit-result', label: '审计完成', icon: '✓', order: 5, lane: 'audit', kind: 'result' },
  ];
  const verifySpecs: Omit<NodeDef, 'x' | 'y'>[] = [
    { id: 'verify-orch', label: '主智能体调度', icon: '✦', order: 0, lane: 'verify', kind: 'orchestrator' },
    { id: 'env', label: '靶机环境搭建', icon: '◈', order: 1, lane: 'verify', kind: 'subagent' },
    { id: 'remote', label: '远程验证', icon: '⦿', order: 2, lane: 'verify', kind: 'subagent' },
    { id: 'chain', label: '组合验证', icon: '◆', order: 3, lane: 'verify', kind: 'subagent' },
    { id: 'verify-result', label: '验证完成', icon: '✓', order: 4, lane: 'verify', kind: 'result' },
  ];
  const auditNodes: NodeDef[] = auditSpecs.map((s, i) => ({ ...s, x: colX(i, gap), y: yAudit }));
  const verifyNodes: NodeDef[] = verifySpecs.map((s, i) => ({ ...s, x: colX(i, gap), y: yVerify }));
  const nodes = [...auditNodes, ...verifyNodes];
  const lastAudit = auditNodes[auditNodes.length - 1];
  const remoteVerify = verifyNodes.find((n) => n.id === 'remote')!;
  const bridge = bridgePath(lastAudit, remoteVerify);
  const edges: EdgeDef[] = [
    ...auditNodes.slice(0, -1).map((n, i) => ({
      ...hEdge(n, auditNodes[i + 1]),
      lane: 'audit' as const,
      targetOrder: auditNodes[i + 1].order,
      fromId: n.id,
      toId: auditNodes[i + 1].id,
    })),
    {
      ...bridge,
      lane: 'bridge',
      targetOrder: remoteVerify.order,
      fromId: lastAudit.id,
      toId: remoteVerify.id,
      label: {
        text: '进入靶机验证',
        x: bridge.mid.x,
        y: bridge.mid.y,
        w: 108,
      },
    },
    ...verifyNodes.slice(0, -1).map((n, i) => ({
      ...hEdge(n, verifyNodes[i + 1]),
      lane: 'verify' as const,
      targetOrder: verifyNodes[i + 1].order,
      fromId: n.id,
      toId: verifyNodes[i + 1].id,
    })),
  ];
  const lastX = Math.max(lastAudit.x, verifyNodes[verifyNodes.length - 1].x);
  return {
    viewW: lastX + NODE_W + PAD_RIGHT,
    viewH: yVerify + NODE_H + PAD_Y,
    nodes,
    edges,
    auditSteps: auditNodes.map((n) => n.label),
    verifySteps: verifyNodes.map((n) => n.label),
  };
}

export default function AgentFlow({
  auditEvents,
  verifyEvents,
  auditRunning,
  verifyRunning,
  auditDone,
  verifyDone,
  envStatus = 'none',
  verifyStarted = false,
  onRunStage,
}: Props) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const uid = useId().replace(/:/g, '');
  const [gap, setGap] = useState(MIN_GAP);
  const layout = useMemo(() => makeLayout(gap), [gap]);

  useLayoutEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const apply = () => {
      const fitted = Math.floor((el.clientWidth - LANE_X - AUDIT_COLS * NODE_W - PAD_RIGHT) / (AUDIT_COLS - 1));
      setGap(Math.max(MIN_GAP, Math.min(fitted, MAX_GAP)));
    };
    apply();
    const ro = new ResizeObserver(apply);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const { statusOf, edgeStatus, currentActivity, caption, stepName, badge, progress, idx } = useMemo(() => {
    const roundAudit = eventsAfterLatestRound(auditEvents);
    const sysHit = (list: AgentEvent[], ...frags: string[]) =>
      list.some((e) => e.kind === 'system' && !!e.text && frags.some((f) => e.text.includes(f)));

    const auditCurFrom = (list: AgentEvent[]) => {
      const subCount = new Set(
        list.filter((e) => e.kind === 'agent_start' && e.tool !== 'Skill').map((e) => e.agent)
      ).size;
      if (sysHit(list, '✓ 实战二次评级完成')) return 5;
      if (sysHit(list, '▶ 红队实战二次评级', '二次评级进度')) return 4;
      if (sysHit(list, '▶ 代码级验证', '代码级验证进度', '✓ 代码级验证完成')) return 3;
      if (sysHit(list, '▶ AI 智能去重', 'AI 去重进度', '✓ AI 智能去重完成')) return 2;
      if (subCount > 0 || sysHit(list, '专项子智能体', '按指定语言', '子智能体覆盖', '路专项')) return 1;
      return 0;
    };

    const roundCur = auditCurFrom(roundAudit);
    const histCur = auditCurFrom(auditEvents);
    // 暂停时不要显示得比历史上已走到的环节更靠前（误点「继续」重跑去重/验证时，看起来会像退了一步）。
    let auditCur = 0;
    if (auditDone) auditCur = 5;
    else if (auditRunning) auditCur = roundCur;
    else auditCur = Math.max(roundCur, histCur);

    const isVerifyCoreMarker = (text: string) =>
      text.includes('▶ 漏洞验证：') ||
      text.includes('▶ 沙箱验证：') ||
      text.includes('▶ 最小运行时验证') ||
      text.includes('▶ 单漏洞远程验证') ||
      text.includes('▶ 单漏洞最小运行时') ||
      text.includes('▶ 单漏洞沙箱验证');
    const isChainMarker = (text: string) =>
      text.includes('组合链验证') ||
      text.includes('组合利用链') ||
      text.includes('▶ 远程验证·组合');
    const coreMarkerIdx = verifyEvents.findIndex(
      (e) => e.kind === 'system' && !!e.text && isVerifyCoreMarker(e.text)
    );
    const chainReached = verifyEvents.some((e) => e.kind === 'system' && !!e.text && isChainMarker(e.text));
    const envBlocksMainFlow =
      verifyStarted && !verifyDone && envStatus !== 'ready' && envStatus !== 'none';
    const remoteCoreStarted = coreMarkerIdx !== -1 && verifyStarted && !auditRunning;

    let verifyCur = -1;
    if (verifyDone) verifyCur = 4;
    else if (envBlocksMainFlow) verifyCur = 1;
    else if (chainReached && verifyStarted && !auditRunning) verifyCur = 3;
    else if (remoteCoreStarted) verifyCur = 2;
    else if (envStatus === 'ready' || envStatus === 'building') verifyCur = 1;
    else if (verifyStarted) verifyCur = 0;

    const byOrder = (order: number, cur: number, laneDone: boolean): NodeStatus =>
      order < cur ? 'done' : order === cur ? (laneDone ? 'done' : 'active') : 'pending';

    const statusOf: Record<string, NodeStatus> = {};
    for (const n of layout.nodes) {
      if (n.lane === 'audit') {
        let st = byOrder(n.order, auditCur, auditDone);
        if (n.id === 'audit-result') {
          st = auditDone ? 'done' : auditRunning && auditCur === n.order ? 'active' : 'pending';
        }
        statusOf[n.id] = st;
      } else {
        let st = byOrder(n.order, verifyCur, verifyDone);
        if (n.id === 'verify-result') {
          st = verifyDone ? 'done' : verifyRunning && verifyCur === n.order ? 'active' : 'pending';
        }
        if (n.id === 'env') {
          if (envStatus === 'ready' && verifyCur >= 1) st = verifyCur > 1 ? 'done' : verifyRunning ? 'active' : 'done';
          else if (envStatus === 'building') st = 'active';
        }
        statusOf[n.id] = st;
      }
    }

    const edgeOf = (
      to: NodeStatus | undefined,
      live: boolean
    ): 'done' | 'flowing' | 'pending' => {
      // 项目/该泳道未在跑：一律灰线静止，不流动。跑起来再按节点状态点亮。
      if (!live) return 'pending';
      if (to === 'done' || to === 'skipped') return 'done';
      if (to === 'active') return 'flowing';
      return 'pending';
    };

    const auditLive = auditRunning;
    const verifyLive = verifyRunning || (auditRunning && envStatus === 'building');

    const edgeStatus = layout.edges.map((e) => {
      if (e.lane === 'bridge') {
        const bridgeLive =
          (auditRunning && (envStatus === 'building' || envStatus === 'ready')) ||
          (auditDone && verifyLive);
        if (!bridgeLive) return 'pending';
        // 从「审计完成」接到「远程验证」：审计没结束不能画成已完成。
        if (!auditDone) {
          if (envStatus === 'building' || envStatus === 'ready') return 'flowing';
          return 'pending';
        }
        if (verifyDone || verifyCur > e.targetOrder) return 'done';
        if (verifyCur === e.targetOrder) return verifyRunning ? 'flowing' : 'done';
        return 'pending';
      }
      if (e.lane === 'audit') return edgeOf(statusOf[e.toId], auditLive);
      return edgeOf(statusOf[e.toId], verifyLive);
    });

    const liveEvents =
      verifyRunning && !auditRunning
        ? verifyEvents
        : auditRunning
          ? roundAudit
          : verifyEvents.length > 0 && verifyStarted
            ? verifyEvents
            : roundAudit;
    let activity = auditRunning || verifyRunning ? '正在初始化…' : '等待开始';
    for (let i = liveEvents.length - 1; i >= 0; i--) {
      const e = liveEvents[i];
      if (e.kind === 'tool_use') {
        const cmd = e.text || '';
        if (/^\s*sleep\s+\d+/.test(cmd)) {
          activity = `主控等待子智能体完成（${cmd.trim()} — 子智能体在后台并发跑靶机，日志可能暂时无更新）`;
          break;
        }
        activity = `${e.agent !== '主控' ? `[${truncate(e.agent, 12)}] ` : ''}${
          TOOL_LABEL[e.tool] || e.tool
        }：${cmd}`;
        break;
      }
      if (e.kind === 'agent_start') {
        activity = `${e.tool === 'Skill' ? '启动技能' : '派发子智能体'}「${e.agent}」`;
        break;
      }
      if ((e.kind === 'text' || e.kind === 'system') && e.text) {
        activity = e.text;
        break;
      }
      if (e.kind === 'result') {
        activity = auditDone && verifyDone ? '验证完成' : auditDone ? '审计完成' : '审计进行中';
        break;
      }
    }

    const caption = !auditDone
      ? `审计阶段 · ${auditCur + 1}/6`
      : verifyDone
        ? '全流程 · 11/11'
        : `验证阶段 · ${Math.max(verifyCur, 0) + 1}/5`;
    const stepName = !auditDone
      ? layout.auditSteps[auditCur]
      : layout.verifySteps[Math.max(verifyCur, 0)];
    const badge = !auditDone ? auditCur + 1 : 6 + Math.max(verifyCur, 0) + 1;
    const doneCount = layout.nodes.filter((n) => statusOf[n.id] === 'done').length;
    const progress = Math.min(100, (doneCount / layout.nodes.length) * 100);
    const idx = !auditDone ? auditCur : 6 + verifyCur;

    return {
      statusOf,
      edgeStatus,
      currentActivity: activity,
      caption,
      stepName,
      badge: Math.min(badge, 11),
      progress,
      idx,
    };
  }, [
    auditEvents,
    verifyEvents,
    auditRunning,
    verifyRunning,
    auditDone,
    verifyDone,
    envStatus,
    verifyStarted,
    layout,
  ]);

  const running = auditRunning || verifyRunning;
  const prevIdx = useRef(-1);
  useEffect(() => {
    if (!wrapRef.current) return;
    if (idx !== prevIdx.current) {
      const el = wrapRef.current.querySelector('.gnode.status-active');
      if (el && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        animate(el, { scale: [0.88, 1], duration: 460, ease: 'outBack' });
      }
      prevIdx.current = idx;
    }
  }, [idx]);

  const hasMovingEdge = edgeStatus.some((status) => status === 'flowing' || status === 'done');

  useEffect(() => {
    const root = wrapRef.current;
    if (!root) return;
    const paths = Array.from(root.querySelectorAll<SVGPathElement>('path.flow-edge'));
    const dots = Array.from(root.querySelectorAll<SVGCircleElement>('circle.edge-pulse'));
    const hideDots = () => dots.forEach((dot) => dot.setAttribute('opacity', '0'));
    hideDots();
    if (!hasMovingEdge) return;

    const moving = paths.flatMap((path, index) => {
      const status = edgeStatus[index];
      if (status !== 'flowing' && status !== 'done') return [];
      try {
        const length = path.getTotalLength();
        return length > 0 && dots[index]
          ? [
              {
                path,
                dot: dots[index],
                length,
                status,
                phase: (index * 0.17) % 1,
                bridge: path.classList.contains('edge-bridge'),
              },
            ]
          : [];
      } catch {
        return [];
      }
    });
    if (moving.length === 0) return;

    const motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    let raf = 0;
    let intersecting = true;
    let start = 0;

    const stop = () => {
      if (raf) cancelAnimationFrame(raf);
      raf = 0;
      hideDots();
    };

    const tick = (t: number) => {
      if (document.visibilityState !== 'visible' || !intersecting || motionQuery.matches) {
        stop();
        return;
      }
      if (!start) start = t;
      const elapsed = t - start;
      moving.forEach(({ path, dot, length, status, phase, bridge }) => {
        const duration = bridge
          ? status === 'flowing'
            ? 8200
            : 11000
          : status === 'flowing'
            ? 1600
            : 2400;
        const fraction = ((elapsed / duration + phase) % 1 + 1) % 1;
        const point = path.getPointAtLength(fraction * length);
        const fade = fraction < 0.12 ? fraction / 0.12 : fraction > 0.88 ? (1 - fraction) / 0.12 : 1;
        dot.setAttribute('cx', String(point.x));
        dot.setAttribute('cy', String(point.y));
        dot.setAttribute('opacity', String(Math.max(0, fade * (status === 'flowing' ? 1 : 0.72))));
      });
      raf = requestAnimationFrame(tick);
    };

    const sync = () => {
      const shouldRun = document.visibilityState === 'visible' && intersecting && !motionQuery.matches;
      if (shouldRun && !raf) {
        start = 0;
        raf = requestAnimationFrame(tick);
      } else if (!shouldRun) {
        stop();
      }
    };

    const observer =
      typeof IntersectionObserver === 'undefined'
        ? null
        : new IntersectionObserver(([entry]) => {
            intersecting = entry?.isIntersecting ?? false;
            sync();
          });
    observer?.observe(root);
    document.addEventListener('visibilitychange', sync);
    motionQuery.addEventListener('change', sync);
    sync();

    return () => {
      stop();
      observer?.disconnect();
      document.removeEventListener('visibilitychange', sync);
      motionQuery.removeEventListener('change', sync);
    };
  }, [edgeStatus, hasMovingEdge]);

  const yAudit = PAD_Y;
  const yVerify = PAD_Y + NODE_H + ROW_GAP;

  return (
    <div className="agent-flow">
      <div className="flow-header">
        <div className="flow-step">
          <span className="step-badge">{badge}</span>
          <div className="step-meta">
            <span className="step-caption">{caption}</span>
            <span className="step-name">{stepName}</span>
          </div>
        </div>
        <div className="flow-progress">
          <div className="flow-progress-bar" style={{ width: `${progress}%` }} />
        </div>
      </div>

      <div className="flow-canvas-scroll" ref={scrollRef}>
        <div className="flow-canvas" ref={wrapRef} style={{ width: layout.viewW, height: layout.viewH }}>
          <span className="flow-lane-tag" style={{ top: yAudit + 18 }}>
            代码审计
          </span>
          <span className="flow-lane-tag" style={{ top: yVerify + 18 }}>
            靶机验证
          </span>
          <svg
            className="flow-edges"
            viewBox={`0 0 ${layout.viewW} ${layout.viewH}`}
            width={layout.viewW}
            height={layout.viewH}
          >
            <defs>
              <filter id={`${uid}-glow`} x="-200%" y="-200%" width="500%" height="500%">
                <feGaussianBlur stdDeviation="2.2" result="b" />
                <feMerge>
                  <feMergeNode in="b" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>
            {layout.edges.map((e, i) => {
              const st = edgeStatus[i];
              return (
                <g key={'e' + i}>
                  <path
                    className={`flow-edge edge-${st}${e.lane === 'bridge' ? ' edge-bridge' : ''}`}
                    d={e.d}
                  />
                  <circle className={`edge-endpoint edge-endpoint-${st}`} cx={e.from.x} cy={e.from.y} r="3.4" />
                  <circle className={`edge-endpoint edge-endpoint-${st}`} cx={e.to.x} cy={e.to.y} r="3.4" />
                </g>
              );
            })}
            {layout.edges.map((_, i) => (
              <circle
                key={'c' + i}
                className={`edge-pulse edge-pulse-${edgeStatus[i]}`}
                r="5"
                opacity="0"
                filter={edgeStatus[i] === 'pending' ? undefined : `url(#${uid}-glow)`}
              />
            ))}
            {layout.edges.map((e, i) =>
              e.label ? (
                <g key={'l' + i}>
                  <rect
                    x={e.label.x - (e.label.w || 68) / 2}
                    y={e.label.y - 13}
                    width={e.label.w || 68}
                    height="20"
                    rx="10"
                    className={`edge-chip edge-chip-${edgeStatus[i]}`}
                  />
                  <text className={`edge-label edge-label-${edgeStatus[i]}`} x={e.label.x} y={e.label.y} dominantBaseline="middle">
                    {e.label.text}
                  </text>
                </g>
              ) : null
            )}
          </svg>

          {layout.nodes.map((n) => (
            <div
              key={n.id}
              className={`gnode kind-${n.kind} status-${statusOf[n.id]}`}
              style={{ left: n.x, top: n.y, width: NODE_W, height: NODE_H }}
              title={n.label}
            >
              <span className="gnode-icon">{statusOf[n.id] === 'done' || statusOf[n.id] === 'skipped' ? '✓' : n.icon}</span>
              <div className="gnode-text">
                <span className="gnode-label">{n.label}</span>
                <span className="gnode-status">
                  {statusOf[n.id] === 'active'
                    ? '进行中'
                    : statusOf[n.id] === 'done'
                      ? '已完成'
                      : statusOf[n.id] === 'skipped'
                        ? '已跳过'
                        : '待执行'}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="flow-status">
        <span className={'flow-led' + (running ? ' on' : '')} />
        <span className="flow-status-text">{currentActivity}</span>
      </div>

      {onRunStage && (
        <div className="stage-runner">
          <span className="stage-runner-label">分环节运行</span>
          <span className="stage-runner-group">
            {AUDIT_STAGES.map((s) => (
                <span className="stage-chip" key={s.stage}>
                  <span className="stage-chip-name">{s.label}</span>
                  <button
                    className="stage-btn"
                    title="从该环节开始，跑到本流程末尾（会连跑后续环节并保持数据一致）"
                    onClick={() => onRunStage!(s.stage, 'from')}
                  >
                    ⏩ 从此重跑
                  </button>
                </span>
            ))}
          </span>
          <span className="stage-runner-sep" aria-hidden="true" />
          <span className="stage-runner-group">
            {VERIFY_STAGES.map((s) => {
              return (
              <span className="stage-chip" key={s.stage}>
                <span className="stage-chip-name">{s.label}</span>
                <button
                  className="stage-btn"
                  title="从该环节开始，跑到本流程末尾（会连跑后续环节并保持数据一致）"
                  onClick={() =>
                    onRunStage!(
                      s.stage,
                      'from',
                      s.stage === 'remote' ? { verify_history: false } : undefined
                    )
                  }
                >
                  ⏩ 从此重跑
                </button>
                {ONLY_OK.has(s.stage) && (
                  <button
                    className="stage-btn"
                    title="只重跑本环节（不影响其它环节）"
                    onClick={() => onRunStage!(s.stage, 'only')}
                  >
                    ▶ 仅此
                  </button>
                )}
              </span>
              );
            })}
          </span>
        </div>
      )}
    </div>
  );
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + '…' : s;
}
