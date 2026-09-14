import {
  createContext,
  memo,
  useContext,
  useEffect,
  useRef,
  useSyncExternalStore,
  type ReactNode,
} from 'react';
import { createPortal } from 'react-dom';
import './Toast.css';

type ToastKind = 'success' | 'error' | 'info';
type ToastItem = { id: number; kind: ToastKind; text: string };
type ToastPush = (text: string, kind?: ToastKind) => void;

type ToastStore = {
  destroy: () => void;
  getSnapshot: () => readonly ToastItem[];
  push: ToastPush;
  subscribe: (listener: () => void) => () => void;
};

const missingProvider: ToastPush = () => {};

const ToastCtx = createContext<ToastPush>(missingProvider);

function createToastStore(): ToastStore {
  let items: readonly ToastItem[] = [];
  let sequence = 0;
  const listeners = new Set<() => void>();
  const timers = new Map<number, number>();

  const emit = () => {
    listeners.forEach((listener) => listener());
  };

  const dismiss = (id: number) => {
    const nextItems = items.filter((item) => item.id !== id);
    if (nextItems.length === items.length) return;

    items = nextItems;
    const timer = timers.get(id);
    if (timer !== undefined) {
      window.clearTimeout(timer);
      timers.delete(id);
    }
    emit();
  };

  return {
    destroy: () => {
      timers.forEach((timer) => window.clearTimeout(timer));
      timers.clear();
      listeners.clear();
      items = [];
    },
    getSnapshot: () => items,
    push: (text, kind = 'info') => {
      const item = { id: ++sequence, kind, text };
      items = [...items, item];
      emit();

      timers.set(
        item.id,
        window.setTimeout(() => dismiss(item.id), 3_200)
      );
    },
    subscribe: (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}

const ToastViewport = memo(function ToastViewport({ store }: { store: ToastStore }) {
  const items = useSyncExternalStore(store.subscribe, store.getSnapshot, store.getSnapshot);

  if (typeof document === 'undefined') return null;

  return createPortal(
    <div className="toast-stack" aria-live="polite" aria-relevant="additions">
      {items.map((toast) => (
        <div
          key={toast.id}
          className={`toast toast-${toast.kind}`}
          role={toast.kind === 'error' ? 'alert' : 'status'}
        >
          <span className="toast-icon" aria-hidden="true">
            {toast.kind === 'success' ? '✓' : toast.kind === 'error' ? '✕' : 'ℹ'}
          </span>
          <span>{toast.text}</span>
        </div>
      ))}
    </div>,
    document.body
  );
});

export function useToast() {
  return useContext(ToastCtx);
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const storeRef = useRef<ToastStore | null>(null);
  if (!storeRef.current) {
    storeRef.current = createToastStore();
  }
  const store = storeRef.current;

  useEffect(() => () => store.destroy(), [store]);

  return (
    <ToastCtx.Provider value={store.push}>
      {children}
      <ToastViewport store={store} />
    </ToastCtx.Provider>
  );
}
