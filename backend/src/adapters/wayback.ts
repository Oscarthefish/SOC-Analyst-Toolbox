import type { IocInput, EnrichmentResult, EnrichOptions } from '../types.js';
import { computeFreshness } from '../lib/freshness.js';
import { resultFactory } from '../lib/result.js';

const PROVIDER_ID = 'wayback';
const PROVIDER_NAME = 'Wayback Machine';
const TIMEOUT_MS = 10_000;
const CDX = 'https://web.archive.org/cdx/search/cdx';
const makeResult = resultFactory(PROVIDER_ID, PROVIDER_NAME);

function parseTimestamp(ts: string): string {
  // CDX timestamps: YYYYMMDDHHmmss (14 chars)
  const y = ts.slice(0, 4);
  const m = ts.slice(4, 6);
  const d = ts.slice(6, 8);
  return `${y}-${m}-${d}`;
}

async function cdxFetch(url: string, signal: AbortSignal): Promise<string[][]> {
  const res = await fetch(url, { signal, headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const json = await res.json() as string[][];
  // First row is header — skip it; return only data rows
  return Array.isArray(json) ? json.slice(1) : [];
}

export async function wayback(ioc: IocInput, _options: EnrichOptions): Promise<EnrichmentResult> {
  if (ioc.type !== 'domain') {
    return makeResult({
      status: 'unsupported_ioc',
      summary: `Wayback Machine does not support IOC type: ${ioc.type} (supports: domain).`,
    });
  }

  const domain = ioc.normalised;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    // Run oldest/newest lookups in parallel
    const [oldestResult, newestResult] = await Promise.allSettled([
      cdxFetch(`${CDX}?url=${encodeURIComponent(domain)}&output=json&fl=timestamp&limit=1`, controller.signal),
      cdxFetch(`${CDX}?url=${encodeURIComponent(domain)}&output=json&fl=timestamp&limit=-1`, controller.signal),
    ]);
    clearTimeout(timeout);

    const oldest = oldestResult.status === 'fulfilled' ? oldestResult.value[0]?.[0] ?? null : null;
    const newest = newestResult.status === 'fulfilled' ? newestResult.value[0]?.[0] ?? null : null;

    if (!oldest) {
      return makeResult({
        status: 'ok',
        summary: `Wayback Machine: No archive snapshots found for ${domain}. Domain may be new or never crawled.`,
        severity: 'unknown',
        confidence: 'low',
        data: { snapshotCount: 0, firstSeen: null, lastSeen: null },
        sourceReliability: 'passive-infra',
        sourceUrl: `https://web.archive.org/web/*/${domain}`,
        keyFacts: [{ label: 'Archive history', value: 'No snapshots found' }],
      });
    }

    const firstDate = parseTimestamp(oldest);
    const lastDate = newest ? parseTimestamp(newest) : firstDate;
    const firstIso = new Date(firstDate).toISOString();
    const ageYears = ((Date.now() - new Date(firstDate).getTime()) / (365.25 * 86_400_000)).toFixed(1);

    return makeResult({
      status: 'ok',
      summary: `Wayback Machine: ${domain} first archived ${firstDate} (~${ageYears} yrs ago). Most recent snapshot: ${lastDate}.`,
      severity: 'unknown',
      confidence: 'medium',
      data: { firstSeen: firstDate, lastSeen: lastDate, ageYears: parseFloat(ageYears) },
      rawAvailable: true,
      sourceUrl: `https://web.archive.org/web/*/${domain}`,
      firstSeenDate: firstIso,
      freshnessLabel: computeFreshness(new Date(lastDate).toISOString()),
      sourceReliability: 'passive-infra',
      keyFacts: [
        { label: 'First archived', value: `${firstDate} (~${ageYears} yrs ago)` },
        { label: 'Latest snapshot', value: lastDate },
        ...(firstDate !== lastDate ? [] : [{ label: 'Note', value: 'Only one snapshot found' }]),
      ],
    });
  } catch (err) {
    clearTimeout(timeout);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({
      status: 'error',
      summary: isTimeout ? 'Wayback Machine request timed out.' : 'Wayback Machine request failed.',
      errorMessage: err instanceof Error ? err.message : String(err),
    });
  }
}
