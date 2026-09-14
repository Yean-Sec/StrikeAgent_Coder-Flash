import { WebSocketServer, WebSocket } from 'ws';
import type { Server } from 'http';

type SubscriptionScope = 'dashboard' | 'projects' | 'monitors';

interface ClientSubscription {
  scopes: ReadonlySet<SubscriptionScope>;
  projectIds: ReadonlySet<string>;
}

const SUBSCRIPTION_SCOPES = new Set<SubscriptionScope>([
  'dashboard',
  'projects',
  'monitors',
]);
const clientSubscriptions = new WeakMap<WebSocket, ClientSubscription>();

let wss: WebSocketServer | null = null;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseSubscription(value: unknown): ClientSubscription | null {
  if (
    !isRecord(value) ||
    value.type !== 'subscribe' ||
    !Array.isArray(value.scopes) ||
    value.scopes.length > 16
  ) {
    return null;
  }

  const scopes = new Set<SubscriptionScope>();
  for (const scope of value.scopes) {
    if (typeof scope !== 'string' || !SUBSCRIPTION_SCOPES.has(scope as SubscriptionScope)) {
      return null;
    }
    scopes.add(scope as SubscriptionScope);
  }

  const rawProjectIds = value.projectIds ?? [];
  if (!Array.isArray(rawProjectIds) || rawProjectIds.length > 5_000) {
    return null;
  }

  const projectIds = new Set<string>();
  for (const projectId of rawProjectIds) {
    if (
      typeof projectId !== 'string' ||
      projectId.length === 0 ||
      projectId.length > 256
    ) {
      return null;
    }
    projectIds.add(projectId);
  }

  return { scopes, projectIds };
}

function hasOwnProjectId(message: Record<string, unknown>): boolean {
  return Object.prototype.hasOwnProperty.call(message, 'projectId');
}

function matchesProject(
  message: Record<string, unknown>,
  subscription: ClientSubscription,
  allowGlobal: boolean
): boolean {
  if (!hasOwnProjectId(message)) return allowGlobal;
  if (typeof message.projectId !== 'string' || message.projectId.length === 0) {
    return false;
  }
  // 空 projectIds 表示订阅该 scope 下的全部项目。
  return (
    subscription.projectIds.size === 0 ||
    subscription.projectIds.has(message.projectId)
  );
}

function shouldReceive(message: unknown, subscription: ClientSubscription): boolean {
  if (!isRecord(message) || typeof message.type !== 'string') return false;

  switch (message.type) {
    case 'hello':
      return true;
    case 'project_status':
      // dashboard 是全局聚合视图，不受 projectIds 限制；无 projectId 的状态是全局失效通知。
      if (subscription.scopes.has('dashboard')) return true;
      return (
        subscription.scopes.has('projects') &&
        matchesProject(message, subscription, true)
      );
    case 'agent_event':
      return (
        subscription.scopes.has('projects') &&
        matchesProject(message, subscription, false)
      );
    case 'monitor_triggered':
      // projectId 是新建项目的附加信息，monitor/dashboard 订阅不应因此被项目过滤遗漏。
      return (
        subscription.scopes.has('monitors') ||
        subscription.scopes.has('dashboard')
      );
    case 'monitor_checked':
      return subscription.scopes.has('monitors');
    default:
      // 已声明订阅的客户端只接收协议白名单消息；旧客户端仍走下方兼容广播。
      return false;
  }
}

export function initWebSocket(server: Server): void {
  wss = new WebSocketServer({ server, path: '/ws' });
  wss.on('connection', (socket) => {
    socket.send(JSON.stringify({ type: 'hello', ts: Date.now() }));
    socket.on('message', (raw, isBinary) => {
      if (isBinary) return;
      try {
        const message: unknown = JSON.parse(raw.toString());
        if (!isRecord(message) || message.type !== 'subscribe') return;
        const subscription = parseSubscription(message);
        // 一旦客户端声明订阅，就不再按旧客户端全量广播；非法声明安全降级为空订阅。
        clientSubscriptions.set(
          socket,
          subscription ?? { scopes: new Set(), projectIds: new Set() }
        );
      } catch {
        /* 忽略非 JSON 客户端消息，保持之前的订阅状态 */
      }
    });
    socket.on('close', () => {
      clientSubscriptions.delete(socket);
    });
  });
}

export function broadcast(message: unknown): void {
  if (!wss) return;
  const data = JSON.stringify(message);
  for (const client of wss.clients) {
    const subscription = clientSubscriptions.get(client);
    // 未发送 subscribe 的旧客户端保持全量广播行为。
    if (
      client.readyState === WebSocket.OPEN &&
      (!subscription || shouldReceive(message, subscription))
    ) {
      client.send(data);
    }
  }
}
