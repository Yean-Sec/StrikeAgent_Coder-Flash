import { useCallback, useEffect, useRef, useState } from 'react';

export type PagedQueryRequest = {
  page: number;
  pageSize: number;
  signal: AbortSignal;
};

export type PagedQueryData<T> = {
  items: readonly T[];
  total: number;
};

export type UsePagedQueryOptions<T> = {
  page: number;
  pageSize: number;
  fetchPage: (request: PagedQueryRequest) => Promise<PagedQueryData<T>>;
  enabled?: boolean;
  initialData?: PagedQueryData<T>;
  keepPreviousData?: boolean;
};

export type UsePagedQueryResult<T> = {
  data: PagedQueryData<T>;
  error: Error | null;
  loading: boolean;
  refetch: () => void;
};

type QueryState<T> = Omit<UsePagedQueryResult<T>, 'refetch'>;

const emptyPage = <T>(): PagedQueryData<T> => ({ items: [], total: 0 });

/**
 * 轻量分页请求状态。AbortController 负责取消，序号校验保证不支持取消的
 * 请求也不会以旧响应覆盖新结果。
 */
export function usePagedQuery<T>({
  page,
  pageSize,
  fetchPage,
  enabled = true,
  initialData,
  keepPreviousData = true,
}: UsePagedQueryOptions<T>): UsePagedQueryResult<T> {
  const requestSequence = useRef(0);
  const [refreshSequence, setRefreshSequence] = useState(0);
  const [state, setState] = useState<QueryState<T>>(() => ({
    data: initialData ?? emptyPage<T>(),
    error: null,
    loading: enabled,
  }));

  const refetch = useCallback(() => {
    setRefreshSequence((sequence) => sequence + 1);
  }, []);

  useEffect(() => {
    const sequence = ++requestSequence.current;

    if (!enabled) {
      setState((current) => ({ ...current, loading: false }));
      return;
    }

    const controller = new AbortController();

    setState((current) => ({
      data: keepPreviousData ? current.data : emptyPage<T>(),
      error: null,
      loading: true,
    }));

    void Promise.resolve()
      .then(() => fetchPage({ page, pageSize, signal: controller.signal }))
      .then((data) => {
        if (controller.signal.aborted || sequence !== requestSequence.current) return;
        setState({ data, error: null, loading: false });
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted || sequence !== requestSequence.current) return;
        setState((current) => ({
          ...current,
          error: error instanceof Error ? error : new Error('分页请求失败'),
          loading: false,
        }));
      });

    return () => controller.abort();
  }, [
    enabled,
    fetchPage,
    keepPreviousData,
    page,
    pageSize,
    refreshSequence,
  ]);

  return { ...state, refetch };
}
