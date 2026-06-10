import fetch from 'node-fetch';
import type { IocInput, EnrichmentResult, EnrichOptions, Severity } from '../types.js';
import { config } from '../config.js';
import { markRateLimited } from '../rateLimit.js';

const PROVIDER_ID = 'pulsedive';
const PROVIDER_NAME = 'Pulsedive';
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

interface RiskFactor {
  description?: string;
  risk?: string;
}

interface PulsediveResponse {
  iid?: number;
  indicator?: string;
  type?: string;
  risk?: string;
  risk_recommended?: string;
  stamp_updated?: string;
  riskfactors?: RiskFactor[];
  threats?: Array<{ name?: string; category?: string }>;
  feeds?: Array<{ name?: string; organization?: string }>;
  properties?: {
    geo?: { country?: string; org?: string; city?: string };
    whois?: { registrar?: string; expires?: string };
    dns?: { a?: string[] };
    ssl?: { subject_cn?: string; valid_to?: string };
  };
  error?: string;
}

function riskToSeverity(risk: string): Severity {
  switch (risk?.toLowerCase()) {
    case 'critical': return 'critical';
    case 'high': return 'high';
    case 'medium': return 'medium';
    case 'low': return 'low';
    case 'none': return 'benign';
    default: return 'unknown';
  }
}

export async function pulsedive(ioc: IocInput, _options: EnrichOptions): Promise<EnrichmentResult> {
  const apiKey = config.pulsedive.apiKey;
  if (!apiKey) {
    return makeResult({ status: 'missing_key', summary: 'Pulsedive API key is not configured.' });
  }

  const supported = ['ipv4', 'ipv6', 'domain', 'url'];
  if (!supported.includes(ioc.type)) {
    return makeResult({ status: 'unsupported_ioc', summary: `Pulsedive does not support IOC type: ${ioc.type}.` });
  }

  const params = new URLSearchParams({ indicator: ioc.normalised, pretty: '1', key: apiKey });
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(`https://pulsedive.com/api/?${params.toString()}`, {
      headers: { Accept: 'application/json' },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (res.status === 429) {
      markRateLimited(PROVIDER_ID);
      return makeResult({ status: 'rate_limited', summary: 'Pulsedive rate limit reached. Try again later.' });
    }
    if (res.status === 401 || res.status === 403) {
      return makeResult({ status: 'error', summary: 'Pulsedive: Invalid API key.', errorMessage: `HTTP ${res.status}` });
    }
    if (!res.ok) {
      return makeResult({ status: 'error', summary: `Pulsedive returned HTTP ${res.status}.`, errorMessage: `HTTP ${res.status}` });
    }

    const body = (await res.json()) as PulsediveResponse;

    if (body.error) {
      if (body.error.toLowerCase().includes('not found')) {
        return makeResult({
          status: 'ok', summary: 'Pulsedive: IOC not found in database.',
          severity: 'unknown', confidence: 'low', data: { found: false },
        });
      }
      return makeResult({ status: 'error', summary: `Pulsedive error: ${body.error}.`, errorMessage: body.error });
    }

    const risk = body.risk ?? 'unknown';
    const severity = riskToSeverity(risk);
    const threats = body.threats?.map(t => t.name ?? '').filter(Boolean) ?? [];
    const feeds = body.feeds?.map(f => f.name ?? '').filter(Boolean) ?? [];
    const riskfactors = body.riskfactors?.map(r => r.description ?? '').filter(Boolean) ?? [];
    const geo = body.properties?.geo;

    let summary = `Pulsedive: Risk rating — ${risk.toUpperCase()}.`;
    if (riskfactors.length) summary += ` Risk factors: ${riskfactors.slice(0, 3).join('; ')}.`;
    if (threats.length) summary += ` Threats: ${threats.join(', ')}.`;
    if (feeds.length) summary += ` Feeds: ${feeds.slice(0, 3).join(', ')}.`;

    return makeResult({
      status: 'ok', summary, severity, confidence: body.iid ? 'high' : 'medium',
      data: {
        risk,
        riskRecommended: body.risk_recommended,
        riskfactors: riskfactors.slice(0, 5),
        threats,
        feeds: feeds.slice(0, 5),
        lastSeen: body.stamp_updated,
        geo: geo ? { country: geo.country, org: geo.org, city: geo.city } : undefined,
        ssl: body.properties?.ssl?.subject_cn ? { cn: body.properties.ssl.subject_cn, validTo: body.properties.ssl.valid_to } : undefined,
      },
      rawAvailable: true,
      sourceUrl: body.iid ? `https://pulsedive.com/indicator/?iid=${body.iid}` : `https://pulsedive.com/indicator/?indicator=${encodeURIComponent(ioc.normalised)}`,
      sourceReliability: 'community' as const,
      keyFacts: [
        { label: 'Risk', value: risk.toUpperCase() },
        ...(threats.length > 0 ? [{ label: 'Threats', value: threats.join(', ') }] : []),
        ...(feeds.length > 0 ? [{ label: 'Feeds', value: String(feeds.length) }] : []),
        ...(riskfactors.length > 0 ? [{ label: 'Risk factors', value: riskfactors[0] ?? '' }] : []),
        ...(body.stamp_updated ? [{ label: 'Last seen', value: body.stamp_updated.split('T')[0] ?? body.stamp_updated }] : []),
      ],
    });
  } catch (err) {
    clearTimeout(timeout);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({ status: 'error', summary: isTimeout ? 'Pulsedive request timed out.' : 'Pulsedive request failed.', errorMessage: err instanceof Error ? err.message : String(err) });
  }
}
