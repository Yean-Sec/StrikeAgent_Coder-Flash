import {
  useCallback,
  useMemo,
  useRef,
  type CSSProperties,
  type HTMLAttributes,
  type ReactNode,
} from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import type { VirtualElementMeasurement } from './VirtualList';
import './Virtual.css';

const TABLE_HEADER_HEIGHT = 44;

export type VirtualTableColumn<T> = {
  id: string;
  header: ReactNode;
  renderCell: (item: T, index: number) => ReactNode;
  align?: 'start' | 'center' | 'end';
  width?: number | string;
};

export type VirtualTableProps<T> = Omit<HTMLAttributes<HTMLDivElement>, 'children'> & {
  columns: readonly VirtualTableColumn<T>[];
  items: readonly T[];
  estimateRowHeight: number | ((item: T, index: number) => number);
  getRowKey: (item: T, index: number) => string | number;
  emptyState?: ReactNode;
  height?: CSSProperties['height'];
  measureElement?: VirtualElementMeasurement;
  overscan?: number;
};

/**
 * 基于 CSS Grid 的语义化虚拟表格，列定义会同时约束表头与数据行。
 */
export function VirtualTable<T>({
  columns,
  items,
  estimateRowHeight,
  getRowKey,
  emptyState = '暂无数据',
  height = 400,
  measureElement = false,
  overscan = 8,
  className,
  role,
  style,
  ...tableProps
}: VirtualTableProps<T>) {
  const scrollRef = useRef<HTMLDivElement>(null);

  const gridTemplateColumns = useMemo(
    () =>
      columns
        .map((column) => {
          if (typeof column.width === 'number') return `${column.width}px`;
          return column.width ?? 'minmax(0, 1fr)';
        })
        .join(' '),
    [columns]
  );

  const getEstimatedSize = useCallback(
    (index: number) => {
      const item = items[index];
      return typeof estimateRowHeight === 'number'
        ? estimateRowHeight
        : estimateRowHeight(item, index);
    },
    [estimateRowHeight, items]
  );

  const getVirtualKey = useCallback(
    (index: number) => getRowKey(items[index], index),
    [getRowKey, items]
  );

  const virtualizer = useVirtualizer<HTMLDivElement, HTMLDivElement>({
    count: items.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: getEstimatedSize,
    getItemKey: getVirtualKey,
    measureElement: typeof measureElement === 'function' ? measureElement : undefined,
    overscan,
    paddingStart: TABLE_HEADER_HEIGHT,
  });

  const shouldMeasure = Boolean(measureElement);
  const virtualRows = virtualizer.getVirtualItems();

  return (
    <div
      {...tableProps}
      className={['virtual-table', className].filter(Boolean).join(' ')}
      role={role ?? 'table'}
      style={style}
      aria-colcount={columns.length}
      aria-rowcount={items.length + 1}
    >
      <div
        ref={scrollRef}
        className="virtual-table__body"
        role="presentation"
        style={{ height }}
        tabIndex={0}
      >
        <div className="virtual-table__head" role="rowgroup">
          <div
            className="virtual-table__header"
            role="row"
            aria-rowindex={1}
            style={{ gridTemplateColumns }}
          >
            {columns.map((column) => (
              <div
                key={column.id}
                className={`virtual-table__header-cell virtual-align-${column.align ?? 'start'}`}
                role="columnheader"
              >
                {column.header}
              </div>
            ))}
          </div>
        </div>

        {items.length === 0 ? (
          <div className="virtual-empty" role="status">
            {emptyState}
          </div>
        ) : (
          <div
            className="virtual-table__rows"
            role="rowgroup"
            style={{ height: virtualizer.getTotalSize() }}
          >
            {virtualRows.map((virtualRow) => {
              const item = items[virtualRow.index];

              return (
                <div
                  key={virtualRow.key}
                  ref={shouldMeasure ? virtualizer.measureElement : undefined}
                  className="virtual-table__row"
                  data-index={virtualRow.index}
                  role="row"
                  aria-rowindex={virtualRow.index + 2}
                  style={{
                    gridTemplateColumns,
                    height: shouldMeasure ? undefined : virtualRow.size,
                    transform: `translateY(${virtualRow.start}px)`,
                  }}
                >
                  {columns.map((column) => (
                    <div
                      key={column.id}
                      className={`virtual-table__cell virtual-align-${column.align ?? 'start'}`}
                      role="cell"
                    >
                      {column.renderCell(item, virtualRow.index)}
                    </div>
                  ))}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
