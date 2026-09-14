export type WSSubscriptionScope = 'dashboard' | 'projects' | 'monitors';
export type WSListener = (msg: any) => void;

export interface WSSubscriptionOptions {
  scope?: WSSubscriptionScope;
  scopes?: readonly WSSubscriptionScope[];
  projectId?: string;
  projectIds?: readonly string[];
}

interface NormalizedSubscription {
  scopes: ReadonlySet<WSSubscriptionScope>;
  // null 表示该 scope 下全部项目；非空集合表示指定项目。
  projectIds: ReadonlySet<string> | null;
}

interface ListenerEntry {
  listener: WSListener;
  // null 保留旧 subscribe(listener) 的全消息语义。
  subscription: NormalizedSubscription | null;
}

interface ProtocolSubscription {
  type: 'subscribe';
  scopes: WSSubscriptionScope[];
  projectIds: string[];
}

const ALL_SCOPES: readonly WSSubscriptionScope[] = [
  'dashboard',
  'projects',
  'monitors',
];
const PROJECT_STATUS_BATCH_MS = 75;
const AGENT_EVENT_BATCH_MS = 16;
const MONITOR_DEBOUNCE_MS = 100;

function isRecord(value: unknown): value is Record<string, any> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function normalizeSubscription(options: WSSubscriptionOptions): NormalizedSubscription {
  const scopes = new Set<WSSubscriptionScope>();
  const hasExplicitScopes =
    options.scope !== undefined || options.scopes !== undefined;
  if (hasExplicitScopes) {
    if (options.scope && ALL_SCOPES.includes(options.scope)) {
      scopes.add(options.scope);
    }
    for (const scope of options.scopes ?? []) {
      if (ALL_SCOPES.includes(scope)) scopes.add(scope);
    }
  } else {
    ALL_SCOPES.forEach((scope) => scopes.add(scope));
  }

  const projectIds = new Set<string>();
  if (options.projectId) projectIds.add(options.projectId);
  for (const projectId of options.projectIds ?? []) {
    if (projectId) projectIds.add(projectId);
  }

  return {
    scopes,
    // 协议约定空 projectIds 为当前 project scope 的通配订阅。
    projectIds: projectIds.size > 0 ? projectIds : null,
  };
}

class WSClient {
  private socket: WebSocket | null = null;
  private listeners = new Set<ListenerEntry>();
  private reconnectTimer: number | null = null;
  private lastSentSubscription: string | null = null;
  private projectStatuses = new Map<string, Record<string, any>>();
  private agentEvents: any[] = [];
  private monitorMessages = new Map<string, Record<string, any>>();
  private projectStatusTimer: number | null = null;
  private agentEventTimer: number | null = null;
  private monitorTimer: number | null = null;

  private connect() {
    if (this.listeners.size === 0) return;
    if (
      this.socket &&
      (this.socket.readyState === WebSocket.CONNECTING ||
        this.socket.readyState === WebSocket.OPEN)
    ) {
      return;
    }
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const socket = new WebSocket(`${proto}://${location.host}/ws`);
    this.socket = socket;
    this.lastSentSubscription = null;

    socket.onopen = () => {
      if (this.socket === socket) this.sendSubscription(true);
    };
    socket.onmessage = (ev) => {
      if (this.socket !== socket || typeof ev.data !== 'string') return;
      try {
        const msg = JSON.parse(ev.data);
        this.receive(msg);
      } catch {
        /* ignore */
      }
    };
    socket.onclose = () => {
      if (this.socket !== socket) return;
      this.socket = null;
      this.lastSentSubscription = null;
      this.scheduleReconnect();
    };
    socket.onerror = () => {
      if (this.socket === socket) socket.close();
    };
  }

  private scheduleReconnect() {
    if (this.listeners.size === 0 || this.reconnectTimer !== null) return;
    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, 1500);
  }

  private aggregateSubscription(): ProtocolSubscription {
    const scopes = new Set<WSSubscriptionScope>();
    const projectIds = new Set<string>();
    let allProjects = false;

    for (const entry of this.listeners) {
      if (entry.subscription === null) {
        ALL_SCOPES.forEach((scope) => scopes.add(scope));
        allProjects = true;
        continue;
      }
      entry.subscription.scopes.forEach((scope) => scopes.add(scope));
      if (!entry.subscription.scopes.has('projects')) continue;
      if (entry.subscription.projectIds === null) {
        allProjects = true;
      } else {
        entry.subscription.projectIds.forEach((projectId) =>
          projectIds.add(projectId)
        );
      }
    }

    return {
      type: 'subscribe',
      scopes: ALL_SCOPES.filter((scope) => scopes.has(scope)),
      projectIds: allProjects ? [] : [...projectIds].sort(),
    };
  }

  private sendSubscription(force = false) {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) return;
    const encoded = JSON.stringify(this.aggregateSubscription());
    if (!force && encoded === this.lastSentSubscription) return;
    try {
      this.socket.send(encoded);
      this.lastSentSubscription = encoded;
    } catch {
      this.socket.close();
    }
  }

  private matchesProject(
    msg: Record<string, any>,
    subscription: NormalizedSubscription,
    allowGlobal: boolean
  ): boolean {
    if (!Object.prototype.hasOwnProperty.call(msg, 'projectId')) {
      return allowGlobal;
    }
    if (typeof msg.projectId !== 'string' || msg.projectId.length === 0) {
      return false;
    }
    return (
      subscription.projectIds === null ||
      subscription.projectIds.has(msg.projectId)
    );
  }

  private matchesSubscription(
    msg: any,
    subscription: NormalizedSubscription
  ): boolean {
    if (!isRecord(msg) || typeof msg.type !== 'string') return false;
    switch (msg.type) {
      case 'hello':
        return true;
      case 'project_status':
        if (subscription.scopes.has('dashboard')) return true;
        return (
          subscription.scopes.has('projects') &&
          this.matchesProject(msg, subscription, true)
        );
      case 'agent_event':
        return (
          subscription.scopes.has('projects') &&
          this.matchesProject(msg, subscription, false)
        );
      case 'monitor_triggered':
        return (
          subscription.scopes.has('monitors') ||
          subscription.scopes.has('dashboard')
        );
      case 'monitor_checked':
        return subscription.scopes.has('monitors');
      default:
        return false;
    }
  }

  private dispatch(msg: any) {
    // 监听器可在回调中取消订阅；快照保证本条消息分发稳定。
    for (const entry of [...this.listeners]) {
      if (
        entry.subscription !== null &&
        !this.matchesSubscription(msg, entry.subscription)
      ) {
        continue;
      }
      try {
        entry.listener(msg);
      } catch {
        /* 单个监听器异常不应阻断其他监听器或 agent_event 顺序 */
      }
    }
  }

  private receive(msg: any) {
    if (!isRecord(msg) || typeof msg.type !== 'string') {
      this.dispatch(msg);
      return;
    }

    if (msg.type === 'hello') {
      this.dispatch(msg);
      return;
    }
    if (msg.type === 'project_status') {
      this.queueProjectStatus(msg);
      return;
    }
    if (msg.type === 'agent_event') {
      this.agentEvents.push(msg);
      if (this.agentEventTimer === null) {
        this.agentEventTimer = window.setTimeout(
          () => this.flushAgentEvents(),
          AGENT_EVENT_BATCH_MS
        );
      }
      return;
    }
    if (msg.type === 'monitor_checked' || msg.type === 'monitor_triggered') {
      const monitorId =
        typeof msg.monitorId === 'string' ? msg.monitorId : '__global__';
      this.monitorMessages.set(`${msg.type}:${monitorId}`, msg);
      if (this.monitorTimer !== null) clearTimeout(this.monitorTimer);
      this.monitorTimer = window.setTimeout(
        () => this.flushMonitorMessages(),
        MONITOR_DEBOUNCE_MS
      );
      return;
    }

    this.dispatch(msg);
  }

  private queueProjectStatus(msg: Record<string, any>) {
    const key =
      typeof msg.projectId === 'string'
        ? `project:${msg.projectId}`
        : '__global__';
    const previous = this.projectStatuses.get(key);
    if (!previous) {
      this.projectStatuses.set(key, msg);
    } else {
      const merged = { ...previous, ...msg };
      // 若后端采用 patch 容器，同样逐字段合并；同名字段以后消息为准。
      if (isRecord(previous.patch) && isRecord(msg.patch)) {
        merged.patch = { ...previous.patch, ...msg.patch };
      }
      this.projectStatuses.set(key, merged);
    }

    if (this.projectStatusTimer === null) {
      this.projectStatusTimer = window.setTimeout(
        () => this.flushProjectStatuses(),
        PROJECT_STATUS_BATCH_MS
      );
    }
  }

  private flushProjectStatuses() {
    this.projectStatusTimer = null;
    const messages = [...this.projectStatuses.values()];
    this.projectStatuses.clear();
    messages.forEach((msg) => this.dispatch(msg));
  }

  private flushAgentEvents() {
    this.agentEventTimer = null;
    const messages = this.agentEvents;
    this.agentEvents = [];
    // 保持接收顺序逐条回调，尤其不能合并或覆盖 delta。
    messages.forEach((msg) => this.dispatch(msg));
  }

  private flushMonitorMessages() {
    this.monitorTimer = null;
    const messages = [...this.monitorMessages.values()];
    this.monitorMessages.clear();
    messages.forEach((msg) => this.dispatch(msg));
  }

  subscribe(
    listener: WSListener,
    options?: WSSubscriptionOptions
  ): () => void {
    const entry: ListenerEntry = {
      listener,
      subscription:
        options === undefined ? null : normalizeSubscription(options),
    };
    this.listeners.add(entry);
    this.connect();
    this.sendSubscription();

    let active = true;
    return () => {
      if (!active) return;
      active = false;
      this.listeners.delete(entry);
      this.sendSubscription();
      if (this.listeners.size === 0 && this.reconnectTimer !== null) {
        clearTimeout(this.reconnectTimer);
        this.reconnectTimer = null;
      }
    };
  }
}

export const wsClient = new WSClient();
