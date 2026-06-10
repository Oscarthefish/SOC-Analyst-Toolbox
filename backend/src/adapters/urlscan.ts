import fetch from 'node-fetch';
import type { IocInput, EnrichmentResult, EnrichOptions, Severity } from '../types.js';
import { config } from '../config.js';
import { markRateLimited } from '../rateLimit.js';
import { maskSensitiveUrl } from '../mask.js';
import { computeFreshness } from '../lib/freshness.js';

const PROVIDER_ID = 'urlscan';
const PROVIDER_NAME = 'urlscan.io';
const TIMEOUT_MS = 10_000;

function now(): string {
  return new Date().toISOString();
}

function makeResult(overrides: Partial<EnrichmentResult>): EnrichmentResult {
  return {
    providerId: PROVIDER_ID,
    providerName: PROVIDER_NAME,
    status: 'ok',
    summary: '',
    severity: 'unknown',
    confidence: 'unknown',
    data: {},
    rawAvailable: false,
    checkedAt: now(),
    fromCache: false,
    ...overrides,
  };
}

interface UrlScanResult {
  page?: {
    title?: string;
    url?: string;
    domain?: string;
  };
  task?: {
    time?: string;
    url?: string;
  };
  verdicts?: {
    overall?: {
      malicious?: boolean;
      score?: number;
    };
  };
  _id?: string;
}

interface UrlScanResponse {
  total?: number;
  results?: UrlScanResult[];
}

function isSensitiveUrl(ioc: IocInput): boolean {
  if (ioc.type !== 'url') return false;
  // Simple heuristic: URL with query params containing token/key/auth/session/password terms
  const lower = ioc.normalised.toLowerCase();
  const sensitiveTerms = ['token=', 'key=', 'auth=', 'session=', 'password=', 'secret=', 'code=', 'api_key='];
  return sensitiveTerms.some(t => lower.includes(t));
}

export async function urlscan(
  ioc: IocInput,
  options: EnrichOptions,
): Promise<EnrichmentResult> {
  if (ioc.type !== 'domain' && ioc.type !== 'url' && ioc.type !== 'ipv4') {
    return makeResult({
      status: 'unsupported_ioc',
      summary: `urlscan.io does not support IOC type: ${ioc.type} (supports: domain, url, ipv4).`,
    });
  }

  // Safety check for sensitive URLs
  if (ioc.type === 'url' && isSensitiveUrl(ioc) && !options.allowSensitiveUrl) {
    return makeResult({
      status: 'skipped_safety',
      summary: `urlscan.io search skipped: URL appears to contain sensitive parameters. Enable "Allow sensitive URL lookups" to proceed.`,
      data: { maskedUrl: maskSensitiveUrl(ioc.normalised) },
    });
  }

  // Build search query
  let query: string;
  switch (ioc.type) {
    case 'domain':
      query = `domain:${ioc.normalised}`;
      break;
    case 'ipv4':
      query = `ip:${ioc.normalised}`;
      break;
    case 'url':
      query = `page.url:${encodeURIComponent(ioc.normalised)}`;
      break;
    default:
      query = ioc.normalised;
  }

  const searchUrl = `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(query)}&size=5`;

  const headers: Record<string, string> = {};
  const apiKey = config.urlscan.apiKey;
  if (apiKey) {
    headers['API-Key'] = apiKey;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(searchUrl, {
      headers,
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (res.status === 429) {
      markRateLimited(PROVIDER_ID);
      return makeResult({
        status: 'rate_limited',
        summary: 'urlscan.io rate limit reached. Try again in 60 seconds.',
      });
    }

    if (!res.ok) {
      return makeResult({
        status: 'error',
        summary: `urlscan.io returned HTTP ${res.status}.`,
        errorMessage: `HTTP ${res.status}`,
      });
    }

    const body = (await res.json()) as UrlScanResponse;
    const total = body.total ?? 0;
    const results = body.results ?? [];

    if (total === 0 || results.length === 0) {
      return makeResult({
        status: 'ok',
        summary: 'urlscan.io: No previous scans found for this IOC.',
        severity: 'unknown',
        confidence: 'low',
        data: { total: 0 },
        sourceUrl: `https://urlscan.io/search/#${encodeURIComponent(query)}`,
      });
    }

    const latest = results[0];
    const overallVerdict = latest.verdicts?.overall;
    const isMalicious = overallVerdict?.malicious ?? false;
    const score = overallVerdict?.score ?? 0;
    const scanTime = latest.task?.time ?? '';
    const pageTitle = latest.page?.title ?? '';

    let severity: Severity;
    let summary: string;

    if (isMalicious) {
      severity = 'high';
      summary = `urlscan.io: Most recent scan flagged as MALICIOUS (score: ${score}). ${total} total scan(s) found. Most recent: ${scanTime || 'unknown'}.`;
    } else if (score > 50) {
      severity = 'medium';
      summary = `urlscan.io: Suspicious verdict (score: ${score}). ${total} total scan(s) found. Most recent: ${scanTime || 'unknown'}.`;
    } else if (total > 0) {
      severity = 'low';
      summary = `urlscan.io: ${total} scan(s) found, no malicious verdict. Most recent: ${scanTime || 'unknown'}${pageTitle ? `, page title: "${pageTitle}"` : ''}.`;
    } else {
      severity = 'unknown';
      summary = 'urlscan.io: No scans found.';
    }

    const isSensitive = ioc.type === 'url' && isSensitiveUrl(ioc);
    const scanDate = scanTime ? new Date(scanTime).toISOString() : undefined;

    return makeResult({
      status: 'ok',
      summary,
      severity,
      confidence: total > 3 ? 'high' : total > 0 ? 'medium' : 'low',
      data: {
        totalScans: total,
        latestScanTime: scanTime,
        isMalicious,
        score,
        pageTitle: isSensitive ? '[redacted]' : pageTitle,
        pageDomain: latest.page?.domain ?? '',
      },
      rawAvailable: true,
      sourceUrl: `https://urlscan.io/search/#${encodeURIComponent(query)}`,
      sourceDataTimestamp: scanDate,
      lastSeenDate: scanDate,
      freshnessLabel: computeFreshness(scanDate),
      sourceReliability: 'commercial-ti',
      keyFacts: [
        { label: 'Total scans', value: String(total) },
        { label: 'Latest verdict', value: isMalicious ? 'MALICIOUS' : score > 50 ? 'Suspicious' : 'No malicious verdict' },
        ...(score > 0 ? [{ label: 'Score', value: String(score) }] : []),
        ...(!isSensitive && pageTitle ? [{ label: 'Page title', value: pageTitle }] : []),
        ...(scanTime ? [{ label: 'Latest scan', value: scanTime }] : []),
      ],
    });
  } catch (err) {
    clearTimeout(timeout);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({
      status: 'error',
      summary: isTimeout ? 'urlscan.io request timed out.' : 'urlscan.io request failed.',
      errorMessage: err instanceof Error ? err.message : String(err),
    });
  }
}
