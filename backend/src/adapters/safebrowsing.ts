import fetch from 'node-fetch';
import type { IocInput, EnrichmentResult, EnrichOptions } from '../types.js';
import { config } from '../config.js';

const PROVIDER_ID = 'safebrowsing';
const PROVIDER_NAME = 'Google Safe Browsing';
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

interface SbMatch {
  threatType?: string;
  platformType?: string;
  threat?: { url?: string };
}

interface SbResponse {
  matches?: SbMatch[];
  error?: { code?: number; message?: string };
}

function normaliseToUrl(ioc: IocInput): string {
  if (ioc.type === 'url') return ioc.normalised;
  return `https://${ioc.normalised}`;
}

export async function safebrowsing(ioc: IocInput, _options: EnrichOptions): Promise<EnrichmentResult> {
  const apiKey = config.safebrowsing.apiKey;
  if (!apiKey) {
    return makeResult({ status: 'missing_key', summary: 'Google Safe Browsing API key is not configured.' });
  }

  const supported = ['url', 'domain'];
  if (!supported.includes(ioc.type)) {
    return makeResult({ status: 'unsupported_ioc', summary: `Google Safe Browsing does not support IOC type: ${ioc.type}.` });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'soc-analyst-toolbox', clientVersion: '1.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: normaliseToUrl(ioc) }],
          },
        }),
        signal: controller.signal,
      },
    );
    clearTimeout(timeout);

    if (res.status === 400) {
      return makeResult({ status: 'error', summary: 'Google Safe Browsing: Invalid request.', errorMessage: 'HTTP 400' });
    }
    if (res.status === 403) {
      return makeResult({ status: 'error', summary: 'Google Safe Browsing: API key invalid or quota exceeded.', errorMessage: 'HTTP 403' });
    }
    if (!res.ok) {
      return makeResult({ status: 'error', summary: `Google Safe Browsing returned HTTP ${res.status}.`, errorMessage: `HTTP ${res.status}` });
    }

    const body = (await res.json()) as SbResponse;

    if (body.error) {
      return makeResult({ status: 'error', summary: `Google Safe Browsing error: ${body.error.message ?? 'unknown'}.`, errorMessage: body.error.message });
    }

    if (!body.matches?.length) {
      return makeResult({
        status: 'ok', summary: 'Google Safe Browsing: No threats detected — URL not on any Google blocklist.',
        severity: 'benign', confidence: 'high', data: { matched: false },
        sourceReliability: 'authoritative' as const,
        keyFacts: [{ label: 'Safe Browsing', value: 'Not listed' }],
      });
    }

    const threatTypes = [...new Set(body.matches.map(m => m.threatType ?? 'unknown'))];
    const summary = `Google Safe Browsing: THREAT DETECTED — ${threatTypes.join(', ')}. This URL is on Google's blocklist.`;

    return makeResult({
      status: 'ok', summary, severity: 'high', confidence: 'high',
      data: { threatTypes, matchCount: body.matches.length },
      rawAvailable: true,
      sourceReliability: 'authoritative' as const,
      keyFacts: [
        { label: 'Safe Browsing', value: 'THREAT DETECTED' },
        { label: 'Threat types', value: threatTypes.join(', ') },
      ],
    });
  } catch (err) {
    clearTimeout(timeout);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({ status: 'error', summary: isTimeout ? 'Google Safe Browsing request timed out.' : 'Google Safe Browsing request failed.', errorMessage: err instanceof Error ? err.message : String(err) });
  }
}
