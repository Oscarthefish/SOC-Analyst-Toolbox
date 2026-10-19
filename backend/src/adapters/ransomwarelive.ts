import type { IocInput, EnrichmentResult, EnrichOptions } from '../types.js';

const PROVIDER_ID = 'ransomwarelive';
const PROVIDER_NAME = 'Ransomware.live';
const TIMEOUT_MS = 12_000;
const API_URL = 'https://api.ransomware.live/recentvictims';

function now(): string { return new Date().toISOString(); }

function makeResult(overrides: Partial<EnrichmentResult>): EnrichmentResult {
  return {
    providerId: PROVIDER_ID, providerName: PROVIDER_NAME,
    status: 'ok', summary: '', severity: 'unknown', confidence: 'unknown',
    data: {}, rawAvailable: false, checkedAt: now(), fromCache: false,
    ...overrides,
  };
}

interface RansomwareVictim {
  post_title?: string;
  group_name?: string;
  website?: string;
  published?: string;
  country?: string;
  activity?: string;
  post_url?: string;
  description?: string;
}

// Module-level cache to avoid re-fetching within the same request batch
let cachedVictims: RansomwareVictim[] | null = null;
let cacheTs = 0;
const MEM_TTL_MS = 25 * 60 * 1000; // 25 minutes

async function fetchVictims(): Promise<RansomwareVictim[]> {
  if (cachedVictims && Date.now() - cacheTs < MEM_TTL_MS) return cachedVictims;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(API_URL, {
      headers: { Accept: 'application/json', 'User-Agent': 'SOC-Analyst-Toolbox/1.0' },
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const json = await res.json() as RansomwareVictim[];
    cachedVictims = Array.isArray(json) ? json : [];
    cacheTs = Date.now();
    return cachedVictims;
  } catch (err) {
    clearTimeout(timeout);
    throw err;
  }
}

function extractDomain(website: string | undefined): string {
  if (!website) return '';
  try {
    const url = website.startsWith('http') ? website : `https://${website}`;
    return new URL(url).hostname.replace(/^www\./, '').toLowerCase();
  } catch {
    return website.replace(/^www\./, '').toLowerCase().split('/')[0];
  }
}

export async function ransomwarelive(ioc: IocInput, _options: EnrichOptions): Promise<EnrichmentResult> {
  if (ioc.type !== 'domain' && ioc.type !== 'url') {
    return makeResult({
      status: 'unsupported_ioc',
      summary: `Ransomware.live does not support IOC type: ${ioc.type} (supports: domain, url).`,
    });
  }

  const queryDomain = ioc.type === 'url'
    ? (() => { try { return new URL(ioc.normalised).hostname.replace(/^www\./, ''); } catch { return ioc.normalised; } })()
    : ioc.normalised.replace(/^www\./, '');

  try {
    const victims = await fetchVictims();
    const matches = victims.filter(v => {
      const victimDomain = extractDomain(v.website);
      return victimDomain && (victimDomain === queryDomain || victimDomain.endsWith(`.${queryDomain}`) || queryDomain.endsWith(`.${victimDomain}`));
    });

    if (matches.length === 0) {
      return makeResult({
        status: 'ok',
        summary: 'Ransomware.live: Domain not found in recent ransomware victim listings.',
        severity: 'unknown',
        confidence: 'medium',
        sourceReliability: 'authoritative',
        keyFacts: [{ label: 'Listed as victim', value: 'No' }],
        data: { found: false, totalRecentVictims: victims.length },
        sourceUrl: 'https://www.ransomware.live',
      });
    }

    const top = matches[0];
    const groups = [...new Set(matches.map(m => m.group_name).filter(Boolean))];
    const sectors = [...new Set(matches.map(m => m.activity).filter(Boolean))];
    const published = top.published ?? '';

    const summary = `Ransomware.live: DOMAIN LISTED AS RANSOMWARE VICTIM in ${matches.length} listing(s). ` +
      `Group(s): ${groups.join(', ') || 'unknown'}. ` +
      (top.activity ? `Sector: ${top.activity}. ` : '') +
      (published ? `Published: ${published}.` : '');

    return makeResult({
      status: 'ok',
      summary,
      severity: 'critical',
      confidence: 'high',
      sourceReliability: 'authoritative',
      lastSeenDate: published ? new Date(published).toISOString() : undefined,
      freshnessLabel: published ? (() => {
        const days = (Date.now() - new Date(published).getTime()) / 86_400_000;
        if (days < 1) return 'last24h';
        if (days < 7) return 'last7d';
        if (days < 30) return 'last30d';
        return 'historical';
      })() : 'unknown',
      keyFacts: [
        { label: 'Listed as victim', value: 'YES — ransomware victim' },
        { label: 'Ransomware group(s)', value: groups.join(', ') || 'unknown' },
        ...(sectors.length ? [{ label: 'Sector', value: sectors.join(', ') }] : []),
        ...(top.country ? [{ label: 'Country', value: top.country }] : []),
        ...(published ? [{ label: 'Published', value: published }] : []),
        { label: 'Listings count', value: String(matches.length) },
      ],
      data: {
        found: true,
        listingsCount: matches.length,
        groups,
        sectors,
        country: top.country,
        published,
        postUrl: top.post_url,
        description: top.description,
      },
      rawAvailable: true,
      sourceUrl: top.post_url ?? 'https://www.ransomware.live',
    });
  } catch (err) {
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({
      status: 'error',
      summary: isTimeout ? 'Ransomware.live request timed out.' : 'Ransomware.live request failed.',
      errorMessage: err instanceof Error ? err.message : String(err),
    });
  }
}
