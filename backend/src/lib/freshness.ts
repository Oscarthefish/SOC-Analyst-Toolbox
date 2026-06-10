import type { FreshnessLabel } from '../types.js';

export function computeFreshness(dateStr: string | undefined | null): FreshnessLabel {
  if (!dateStr) return 'unknown';
  const date = new Date(dateStr);
  if (isNaN(date.getTime())) return 'unknown';
  const diffDays = (Date.now() - date.getTime()) / 86_400_000;
  if (diffDays < 1) return 'last24h';
  if (diffDays < 7) return 'last7d';
  if (diffDays < 30) return 'last30d';
  return 'historical';
}
