import type { IocType } from '../types/ioc';
import type { EnrichmentResult, Severity } from '../types/enrichment';
import { detectIoc } from './detectIoc';

export const BATCH_LIMIT = 50;

export type RowStatus = 'pending' | 'running' | 'done' | 'error' | 'skipped';

export interface BatchRow {
  id: string;
  raw: string;
  normalised: string;
  type: IocType;
  status: RowStatus;
  severity?: Severity;
  confidence?: string;
  /** Providers that returned data / providers queried */
  sources?: { withData: number; total: number };
  topFinding?: string;
  errorMsg?: string;
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, benign: 4, unknown: 5,
};

/** Split pasted text into unique indicators (one per line or comma-separated), capped at BATCH_LIMIT. */
export function parseBatchInput(raw: string): { rows: BatchRow[]; truncated: number } {
  const tokens = raw.split(/[\n,]+/).map(l => l.trim()).filter(Boolean);
  const seen = new Set<string>();
  const rows: BatchRow[] = [];
  let truncated = 0;
  for (const token of tokens) {
    const detected = detectIoc(token);
    const key = detected.normalised || token;
    if (seen.has(key)) continue;
    seen.add(key);
    if (rows.length >= BATCH_LIMIT) { truncated++; continue; }
    rows.push({
      id: key,
      raw: token,
      normalised: key,
      type: detected.type,
      status: detected.type === 'unknown' || detected.isEmailHeader ? 'skipped' : 'pending',
    });
  }
  return { rows, truncated };
}

/** The most severe provider finding, as one line. */
export function topFinding(results: EnrichmentResult[]): string {
  const best = results
    .filter(r => r.status === 'ok' || r.status === 'cached')
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9))[0];
  if (!best) return 'No data returned.';
  const kf = best.keyFacts?.[0];
  return kf ? `[${best.providerName}] ${kf.label}: ${kf.value}` : best.summary;
}

function csvCell(value: string): string {
  // Quote when needed, and neutralise spreadsheet formula injection (=, +, -, @)
  const safe = /^[=+\-@]/.test(value) ? `'${value}` : value;
  return /[",\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

export function rowsToCsv(rows: BatchRow[]): string {
  const header = ['indicator', 'type', 'status', 'severity', 'confidence', 'sources_with_data', 'sources_queried', 'top_finding'];
  const lines = rows.map(r => [
    r.normalised, r.type, r.status, r.severity ?? '', r.confidence ?? '',
    r.sources ? String(r.sources.withData) : '', r.sources ? String(r.sources.total) : '',
    r.errorMsg ?? r.topFinding ?? '',
  ].map(csvCell).join(','));
  return [header.join(','), ...lines].join('\n') + '\n';
}
