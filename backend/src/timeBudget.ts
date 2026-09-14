export async function withinBudget<T>(
  task: Promise<T>,
  budgetMs: number
): Promise<{ timedOut: false; value: T } | { timedOut: true }> {
  if (budgetMs <= 0) return { timedOut: true };
  let timer: NodeJS.Timeout | null = null;
  try {
    return await Promise.race([
      task.then((value) => ({ timedOut: false as const, value })),
      new Promise<{ timedOut: true }>((resolve) => {
        timer = setTimeout(() => resolve({ timedOut: true }), budgetMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
