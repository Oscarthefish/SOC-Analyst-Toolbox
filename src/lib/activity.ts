import type { Severity } from '../types/enrichment';
import { countSeverities } from './severityMix';
import type { Bucket } from './severityMix';

export interface DayColumn {
  key: string;
  label: string;
  mix: Record<Bucket, number>;
}

const DAY_MS = 86_400_000;

const startOfDay = (d: Date) => new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();

/** Seven local-time days ending today, each with the severity mix of items saved that day. */
export function lastSevenDays(items: { savedAt: string; result: { overall: { severity: Severity } } }[], now = new Date()): DayColumn[] {
  const today = startOfDay(now);
  return Array.from({ length: 7 }, (_, i) => {
    const dayStart = today - (6 - i) * DAY_MS;
    const sevs = items
      .filter(e => { const t = new Date(e.savedAt).getTime(); return t >= dayStart && t < dayStart + DAY_MS; })
      .map(e => e.result.overall.severity);
    const label = i === 6 ? 'Today' : new Date(dayStart).toLocaleDateString(undefined, { weekday: 'short' });
    return { key: String(dayStart), label, mix: countSeverities(sevs) };
  });
}

export interface CategoryDay {
  key: string;
  label: string;
  values: Record<string, number>;
}

/** `days` local-time days ending today, counting items per category. Items outside the window are ignored. */
export function dailyCounts<T>(items: T[], dateOf: (item: T) => string, categoryOf: (item: T) => string, days: number, now = new Date()): CategoryDay[] {
  const today = startOfDay(now);
  const cols: CategoryDay[] = Array.from({ length: days }, (_, i) => {
    const dayStart = today - (days - 1 - i) * DAY_MS;
    return { key: String(dayStart), label: new Date(dayStart).toLocaleDateString(undefined, { day: 'numeric', month: 'short' }), values: {} };
  });
  const first = today - (days - 1) * DAY_MS;
  for (const item of items) {
    const t = new Date(dateOf(item)).getTime();
    if (Number.isNaN(t) || t < first) continue;
    const idx = Math.floor((startOfDay(new Date(t)) - first) / DAY_MS);
    const col = cols[idx];
    if (!col) continue;
    const cat = categoryOf(item);
    col.values[cat] = (col.values[cat] ?? 0) + 1;
  }
  return cols;
}

/** Count values and return them most frequent first, skipping blanks and the given placeholders. */
export function topCounts(values: (string | undefined | null)[], ignore: string[] = []): { label: string; value: number }[] {
  const skip = new Set(ignore.map(s => s.toLowerCase()));
  const counts = new Map<string, number>();
  for (const v of values) {
    const s = v?.trim();
    if (!s || skip.has(s.toLowerCase())) continue;
    counts.set(s, (counts.get(s) ?? 0) + 1);
  }
  return [...counts.entries()].map(([label, value]) => ({ label, value })).sort((a, b) => b.value - a.value || a.label.localeCompare(b.label));
}
