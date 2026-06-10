import fetch from 'node-fetch';
import type { IocInput, EnrichmentResult, EnrichOptions, Severity } from '../types.js';
import { config } from '../config.js';
import { markRateLimited } from '../rateLimit.js';

const PROVIDER_ID = 'hibp';
const PROVIDER_NAME = 'HaveIBeenPwned';
const TIMEOUT_MS = 10_000;

function now(): string { return new Date().toISOString(); }

function makeResult(overrides: Partial<EnrichmentResult>): EnrichmentResult {
  return {
    providerId: PROVIDER_ID, providerName: PROVIDER_NAME,
    status: 'ok', summary: '', severity: 'unknown', confidence: 'unknown',
    data: {}, rawAvailable: false, checkedAt: now(), fromCache: false,
    ...overrides,
  };
}

interface HibpBreach {
  Name?: string;
  Title?: string;
  Domain?: string;
  BreachDate?: string;
  PwnCount?: number;
  DataClasses?: string[];
  IsVerified?: boolean;
  IsSensitive?: boolean;
}

export async function hibp(ioc: IocInput, _options: EnrichOptions): Promise<EnrichmentResult> {
  const apiKey = config.hibp.apiKey;
  if (!apiKey) {
    return makeResult({ status: 'missing_key', summary: 'HaveIBeenPwned API key is not configured.' });
  }

  if (ioc.type !== 'email') {
    return makeResult({ status: 'unsupported_ioc', summary: `HaveIBeenPwned only supports email addresses (got: ${ioc.type}).` });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(ioc.normalised)}?truncateResponse=false`,
      {
        headers: {
          'hibp-api-key': apiKey,
          'User-Agent': 'SOC-Analyst-Toolbox',
        },
        signal: controller.signal,
      },
    );
    clearTimeout(timeout);

    if (res.status === 404) {
      return makeResult({
        status: 'ok', summary: 'HaveIBeenPwned: Email address not found in any known breach.',
        severity: 'benign', confidence: 'high', data: { breachCount: 0 },
        sourceUrl: `https://haveibeenpwned.com/account/${encodeURIComponent(ioc.normalised)}`,
      });
    }
    if (res.status === 429) {
      markRateLimited(PROVIDER_ID);
      return makeResult({ status: 'rate_limited', summary: 'HaveIBeenPwned rate limit reached. Try again in 60 seconds.' });
    }
    if (res.status === 401) {
      return makeResult({ status: 'error', summary: 'HaveIBeenPwned: Invalid API key.', errorMessage: 'HTTP 401' });
    }
    if (!res.ok) {
      return makeResult({ status: 'error', summary: `HaveIBeenPwned returned HTTP ${res.status}.`, errorMessage: `HTTP ${res.status}` });
    }

    const breaches = (await res.json()) as HibpBreach[];
    const count = breaches.length;
    const sensitiveCount = breaches.filter(b => b.IsSensitive).length;
    const dataClasses = [...new Set(breaches.flatMap(b => b.DataClasses ?? []))].slice(0, 8);
    const latestBreach = breaches.sort((a, b) => (b.BreachDate ?? '').localeCompare(a.BreachDate ?? ''))[0];
    const breachNames = breaches.slice(0, 5).map(b => b.Title ?? b.Name ?? '').filter(Boolean);

    let severity: Severity;
    if (count >= 10 || sensitiveCount > 0) severity = 'high';
    else if (count >= 3) severity = 'medium';
    else severity = 'low';

    const summary = `HaveIBeenPwned: Email found in ${count} breach(es).${sensitiveCount ? ` ${sensitiveCount} sensitive.` : ''} Latest: ${latestBreach?.Title ?? 'unknown'} (${latestBreach?.BreachDate ?? 'unknown'}). Exposed data: ${dataClasses.join(', ') || 'unknown'}.`;

    return makeResult({
      status: 'ok', summary, severity, confidence: 'high',
      data: { breachCount: count, sensitiveCount, dataClasses, latestBreach: latestBreach?.Title, latestBreachDate: latestBreach?.BreachDate, breachNames },
      rawAvailable: true,
      sourceUrl: `https://haveibeenpwned.com/account/${encodeURIComponent(ioc.normalised)}`,
      sourceReliability: 'authoritative' as const,
      keyFacts: [
        { label: 'Breaches', value: `${count}${sensitiveCount > 0 ? ` (${sensitiveCount} sensitive)` : ''}` },
        ...(latestBreach?.Title ? [{ label: 'Latest breach', value: `${latestBreach.Title}${latestBreach.BreachDate ? ` (${latestBreach.BreachDate})` : ''}` }] : []),
        ...(dataClasses.length > 0 ? [{ label: 'Exposed data', value: dataClasses.slice(0, 4).join(', ') }] : []),
        ...(breachNames.length > 0 ? [{ label: 'Breach names', value: breachNames.join(', ') }] : []),
      ],
    });
  } catch (err) {
    clearTimeout(timeout);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({ status: 'error', summary: isTimeout ? 'HaveIBeenPwned request timed out.' : 'HaveIBeenPwned request failed.', errorMessage: err instanceof Error ? err.message : String(err) });
  }
}
