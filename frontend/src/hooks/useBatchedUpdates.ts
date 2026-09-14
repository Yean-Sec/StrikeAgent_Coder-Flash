import { useCallback, useEffect, useMemo, useRef } from 'react';

export type BatchedUpdates<T> = {
  enqueue: (update: T) => void;
  flush: () => void;
};

/**
 * 将同一帧内的高频更新合并后一次交给调用方，适合 WebSocket 消息等场景。
 */
export function useBatchedUpdates<T>(
  onFlush: (updates: readonly T[]) => void
): BatchedUpdates<T> {
  const onFlushRef = useRef(onFlush);
  const queueRef = useRef<T[]>([]);
  const frameRef = useRef<number | null>(null);
  const activeRef = useRef(true);
  onFlushRef.current = onFlush;

  const flush = useCallback(() => {
    if (frameRef.current !== null) {
      window.cancelAnimationFrame(frameRef.current);
      frameRef.current = null;
    }
    if (!activeRef.current || queueRef.current.length === 0) return;

    const updates = queueRef.current;
    queueRef.current = [];
    onFlushRef.current(updates);
  }, []);

  const enqueue = useCallback(
    (update: T) => {
      if (!activeRef.current) return;

      queueRef.current.push(update);
      if (frameRef.current === null) {
        frameRef.current = window.requestAnimationFrame(flush);
      }
    },
    [flush]
  );

  useEffect(() => {
    activeRef.current = true;

    return () => {
      activeRef.current = false;
      queueRef.current = [];
      if (frameRef.current !== null) {
        window.cancelAnimationFrame(frameRef.current);
        frameRef.current = null;
      }
    };
  }, []);

  return useMemo(() => ({ enqueue, flush }), [enqueue, flush]);
}
