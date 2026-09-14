import {
  useCallback,
  useRef,
  type CSSProperties,
  type HTMLAttributes,
  type ReactNode,
} from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import './Virtual.css';

export type VirtualElementMeasurement = boolean | ((
  element: HTMLDivElement,
  entry: ResizeObserverEntry | undefined
) => number);

export type VirtualListProps<T> = Omit<HTMLAttributes<HTMLDivElement>, 'children'> & {
  items: readonly T[];
  estimateSize: number | ((item: T, index: number) => number);
  getItemKey: (item: T, index: number) => string | number;
  renderItem: (item: T, index: number) => ReactNode;
  emptyState?: ReactNode;
  height?: CSSProperties['height'];
  measureElement?: VirtualElementMeasurement;
  overscan?: number;
};

/**
 * 只渲染可视区附近的列表项。固定高度时传数字 estimateSize；
 * 可变高度时同时开启 measureElement。
 */
export function VirtualList<T>({
  items,
  estimateSize,
  getItemKey,
  renderItem,
  emptyState = '暂无数据',
  height = 400,
  measureElement = false,
  overscan = 6,
  className,
  role,
  style,
  tabIndex,
  ...scrollProps
}: VirtualListProps<T>) {
  const scrollRef = useRef<HTMLDivElement>(null);

  const getEstimatedSize = useCallback(
    (index: number) => {
      const item = items[index];
      return typeof estimateSize === 'number'
        ? estimateSize
        : estimateSize(item, index);
    },
    [estimateSize, items]
  );

  const getVirtualKey = useCallback(
    (index: number) => getItemKey(items[index], index),
    [getItemKey, items]
  );

  const virtualizer = useVirtualizer<HTMLDivElement, HTMLDivElement>({
    count: items.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: getEstimatedSize,
    getItemKey: getVirtualKey,
    measureElement: typeof measureElement === 'function' ? measureElement : undefined,
    overscan,
  });

  const shouldMeasure = Boolean(measureElement);
  const virtualItems = virtualizer.getVirtualItems();

  return (
    <div
      {...scrollProps}
      ref={scrollRef}
      className={['virtual-list', className].filter(Boolean).join(' ')}
      role={role ?? 'list'}
      style={{ ...style, height }}
      tabIndex={tabIndex ?? 0}
    >
      {items.length === 0 ? (
        <div className="virtual-empty" role="status">
          {emptyState}
        </div>
      ) : (
        <div
          className="virtual-list__inner"
          style={{ height: virtualizer.getTotalSize() }}
        >
          {virtualItems.map((virtualItem) => {
            const item = items[virtualItem.index];

            return (
              <div
                key={virtualItem.key}
                ref={shouldMeasure ? virtualizer.measureElement : undefined}
                className="virtual-list__item"
                data-index={virtualItem.index}
                role="listitem"
                style={{
                  height: shouldMeasure ? undefined : virtualItem.size,
                  transform: `translateY(${virtualItem.start}px)`,
                }}
              >
                {renderItem(item, virtualItem.index)}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
