import type { EnrichmentResult, Severity } from '../types/enrichment';

/**
 * How a set of provider results splits across the severity scale. Drives the
 * provider matrix, the verdict gauge and the history/case charts.
 */

export type Bucket = 'critical' | 'high' | 'medium' | 'low' | 'benign' | 'info' | 'none';

export const BUCKET_ORDER: Bucket[] = ['critical', 'high', 'medium', 'low', 'benign', 'info', 'none'];

export const BUCKET_LABEL: Record<Bucket, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  benign: 'Benign',
  info: 'Context only',
  none: 'No data',
};

export const hasData = (r: EnrichmentResult) => r.status === 'ok' || r.status === 'cached';

/** A provider that answered but gave no risk opinion is "context only"; one that didn't answer is "no data". */
export function bucketOf(r: EnrichmentResult): Bucket {
  if (!hasData(r)) return 'none';
  return r.severity === 'unknown' ? 'info' : r.severity;
}

export function severityMix(results: EnrichmentResult[]): Record<Bucket, number> {
  const mix = Object.fromEntries(BUCKET_ORDER.map(b => [b, 0])) as Record<Bucket, number>;
  for (const r of results) mix[bucketOf(r)] += 1;
  return mix;
}

/** Providers with data that rated the indicator medium or worse. */
export function flaggedCount(results: EnrichmentResult[]): number {
  return results.filter(r => hasData(r) && (r.severity === 'critical' || r.severity === 'high' || r.severity === 'medium')).length;
}

/** Count a list of overall severities (history entries, cases) on the same scale. */
export function countSeverities(severities: Severity[]): Record<Bucket, number> {
  const mix = Object.fromEntries(BUCKET_ORDER.map(b => [b, 0])) as Record<Bucket, number>;
  for (const s of severities) mix[s === 'unknown' ? 'info' : s] += 1;
  return mix;
}
