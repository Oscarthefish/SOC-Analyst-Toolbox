import fetch from 'node-fetch';
import type { IocInput, EnrichmentResult, EnrichOptions, Severity } from '../types.js';
import { config } from '../config.js';
import { markRateLimited } from '../rateLimit.js';
import { computeFreshness } from '../lib/freshness.js';

const PROVIDER_ID = 'otx';
const PROVIDER_NAME = 'AlienVault OTX';
const TIMEOUT_MS = 10_000;
const BASE = 'https://otx.alienvault.com/api/v1/indicators';

function now(): string { return new Date().toISOString(); }

function makeResult(overrides: Partial<EnrichmentResult>): EnrichmentResult {
  return {
    providerId: PROVIDER_ID, providerName: PROVIDER_NAME,
    status: 'ok', summary: '', severity: 'unknown', confidence: 'unknown',
    data: {}, rawAvailable: false, checkedAt: now(), fromCache: false,
    ...overrides,
  };
}

interface OtxGeneral {
  pulse_info?: { count?: number; pulses?: Array<{ name?: string; tags?: string[] }> };
  reputation?: number;
  country_name?: string;
  asn?: string;
  indicator?: string;
  validation?: unknown[];
}

function iocTypeToOtxPath(ioc: IocInput): string | null {
  switch (ioc.type) {
    case 'ipv4': return `IPv4/${ioc.normalised}/general`;
    case 'ipv6': return `IPv6/${ioc.normalised}/general`;
    case 'domain': return `domain/${ioc.normalised}/general`;
    case 'url': return `url/${encodeURIComponent(ioc.normalised)}/general`;
    case 'md5':
    case 'sha1':
    case 'sha256': return `file/${ioc.normalised}/general`;
    default: return null;
  }
}

export async function otx(ioc: IocInput, _options: EnrichOptions): Promise<EnrichmentResult> {
  const apiKey = config.otx.apiKey;
  if (!apiKey) {
    return makeResult({ status: 'missing_key', summary: 'AlienVault OTX API key is not configured.' });
  }

  const path = iocTypeToOtxPath(ioc);
  if (!path) {
    return makeResult({ status: 'unsupported_ioc', summary: `OTX does not support IOC type: ${ioc.type}.` });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(`${BASE}/${path}`, {
      headers: { 'X-OTX-API-KEY': apiKey, Accept: 'application/json' },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (res.status === 429) {
      markRateLimited(PROVIDER_ID);
      return makeResult({ status: 'rate_limited', summary: 'OTX rate limit reached. Try again later.' });
    }
    if (res.status === 401 || res.status === 403) {
      return makeResult({ status: 'error', summary: 'OTX: Invalid or unauthorised API key.', errorMessage: `HTTP ${res.status}` });
    }
    if (!res.ok) {
      return makeResult({ status: 'error', summary: `OTX returned HTTP ${res.status}.`, errorMessage: `HTTP ${res.status}` });
    }

    const body = (await res.json()) as OtxGeneral;
    const pulseCount = body.pulse_info?.count ?? 0;
    const reputation = body.reputation ?? 0;
    const pulses = body.pulse_info?.pulses ?? [];
    const pulseTags = [...new Set(pulses.flatMap(p => p.tags ?? []))].slice(0, 8);
    const pulseNames = pulses.slice(0, 3).map(p => p.name ?? '').filter(Boolean);

    let severity: Severity;
    if (pulseCount === 0 && reputation === 0) {
      severity = 'unknown';
    } else if (pulseCount >= 10 || reputation >= 3) {
      severity = 'high';
    } else if (pulseCount >= 3 || reputation >= 1) {
      severity = 'medium';
    } else {
      severity = 'low';
    }

    let summary: string;
    if (pulseCount === 0) {
      summary = `OTX: No threat pulses found for this IOC — not observed in community threat intelligence.`;
    } else {
      summary = `OTX: Found in ${pulseCount} threat pulse(s).${pulseNames.length ? ` Campaigns: ${pulseNames.join('; ')}.` : ''}${pulseTags.length ? ` Tags: ${pulseTags.join(', ')}.` : ''}`;
    }

    const indicatorPath = ioc.type === 'ipv4' || ioc.type === 'ipv6' ? 'ip'
      : ioc.type === 'md5' || ioc.type === 'sha1' || ioc.type === 'sha256' ? 'file'
      : ioc.type;

    return makeResult({
      status: 'ok', summary, severity, confidence: pulseCount > 0 ? 'high' : 'medium',
      data: { pulseCount, reputation, pulseTags, topPulses: pulseNames, country: body.country_name, asn: body.asn },
      rawAvailable: true,
      sourceUrl: `https://otx.alienvault.com/indicator/${indicatorPath}/${ioc.normalised}`,
      sourceReliability: 'community',
      freshnessLabel: computeFreshness(undefined),
      keyFacts: [
        { label: 'Pulse count', value: String(pulseCount) },
        { label: 'Reputation', value: String(reputation) },
        ...(pulseTags.length ? [{ label: 'Tags', value: pulseTags.join(', ') }] : []),
        ...(pulseNames.length ? [{ label: 'Top campaigns', value: pulseNames.join('; ') }] : []),
        ...(body.country_name ? [{ label: 'Country', value: body.country_name }] : []),
        ...(body.asn ? [{ label: 'ASN', value: body.asn }] : []),
      ],
    });
  } catch (err) {
    clearTimeout(timeout);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({ status: 'error', summary: isTimeout ? 'OTX request timed out.' : 'OTX request failed.', errorMessage: err instanceof Error ? err.message : String(err) });
  }
}
