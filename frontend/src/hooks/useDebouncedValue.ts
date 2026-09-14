import { useEffect, useState } from 'react';

/**
 * 仅在值停止变化一段时间后更新，适合搜索词和筛选条件。
 */
export function useDebouncedValue<T>(value: T, delay = 250): T {
  const [debouncedValue, setDebouncedValue] = useState(value);

  useEffect(() => {
    const timer = window.setTimeout(
      () => setDebouncedValue(value),
      Math.max(0, delay)
    );

    return () => window.clearTimeout(timer);
  }, [delay, value]);

  return debouncedValue;
}
