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
