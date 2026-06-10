import fetch from 'node-fetch';
import type { IocInput, EnrichmentResult, EnrichOptions, Severity } from '../types.js';
import { config } from '../config.js';
import { markRateLimited } from '../rateLimit.js';
import { computeFreshness } from '../lib/freshness.js';

const PROVIDER_ID = 'virustotal';
const PROVIDER_NAME = 'VirusTotal';
const TIMEOUT_MS = 10_000;
const BASE_URL = 'https://www.virustotal.com/api/v3';

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

interface VtAnalysisStats {
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
}

interface VtAttributes {
  last_analysis_stats?: VtAnalysisStats;
  reputation?: number;
  last_analysis_date?: number;
  meaningful_name?: string;
  popular_threat_category?: string;
  categories?: Record<string, string>;
}

interface VtResponse {
  data?: {
    attributes?: VtAttributes;
    id?: string;
  };
  error?: {
    code?: string;
    message?: string;
  };
}

function getEndpoint(ioc: IocInput): string | null {
  switch (ioc.type) {
    case 'ipv4':
    case 'ipv6':
      return `${BASE_URL}/ip_addresses/${encodeURIComponent(ioc.normalised)}`;
    case 'domain':
      return `${BASE_URL}/domains/${encodeURIComponent(ioc.normalised)}`;
    case 'md5':
    case 'sha1':
    case 'sha256':
      return `${BASE_URL}/files/${ioc.normalised}`;
    default:
      return null;
  }
}

function getSourceUrl(ioc: IocInput): string {
  switch (ioc.type) {
    case 'ipv4':
    case 'ipv6':
      return `https://www.virustotal.com/gui/ip-address/${ioc.normalised}`;
    case 'domain':
      return `https://www.virustotal.com/gui/domain/${ioc.normalised}`;
    default:
      return `https://www.virustotal.com/gui/file/${ioc.normalised}`;
  }
}

export async function virustotal(
  ioc: IocInput,
  _options: EnrichOptions,
): Promise<EnrichmentResult> {
  // URL scanning is explicitly not supported in Phase 3
  if (ioc.type === 'url') {
    return makeResult({
      status: 'unsupported_ioc',
      summary:
        'VirusTotal URL scanning is not supported in Phase 3 (requires URL ID computation and potential submission). Use the domain extracted from the URL instead.',
    });
  }

  if (
    ioc.type !== 'ipv4' &&
    ioc.type !== 'ipv6' &&
    ioc.type !== 'domain' &&
    ioc.type !== 'md5' &&
    ioc.type !== 'sha1' &&
    ioc.type !== 'sha256'
  ) {
    return makeResult({
      status: 'unsupported_ioc',
      summary: `VirusTotal does not support IOC type: ${ioc.type}.`,
    });
  }

  const apiKey = config.virustotal.apiKey;
  if (!apiKey) {
    return makeResult({
      status: 'missing_key',
      summary: 'VirusTotal API key is not configured.',
    });
  }

  const endpoint = getEndpoint(ioc);
  if (!endpoint) {
    return makeResult({
      status: 'unsupported_ioc',
      summary: `No VirusTotal endpoint for IOC type: ${ioc.type}.`,
    });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(endpoint, {
      headers: { 'x-apikey': apiKey },
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (res.status === 429) {
      markRateLimited(PROVIDER_ID);
      return makeResult({
        status: 'rate_limited',
        summary: 'VirusTotal rate limit reached. Try again in 60 seconds.',
      });
    }

    if (res.status === 404) {
      return makeResult({
        status: 'ok',
        summary: 'VirusTotal has no data for this IOC.',
        severity: 'unknown',
        confidence: 'low',
        data: { inDataset: false },
        sourceUrl: getSourceUrl(ioc),
      });
    }

    if (!res.ok) {
      return makeResult({
        status: 'error',
        summary: `VirusTotal returned HTTP ${res.status}.`,
        errorMessage: `HTTP ${res.status}`,
      });
    }

    const body = (await res.json()) as VtResponse;

    if (body.error) {
      return makeResult({
        status: 'error',
        summary: `VirusTotal error: ${body.error.message ?? 'unknown'}.`,
        errorMessage: body.error.message ?? 'Unknown error',
      });
    }

    const attrs = body.data?.attributes;
    if (!attrs) {
      return makeResult({
        status: 'error',
        summary: 'VirusTotal returned an unexpected response format.',
        errorMessage: 'No attributes in response',
      });
    }

    const stats = attrs.last_analysis_stats ?? {};
    const malicious = stats.malicious ?? 0;
    const suspicious = stats.suspicious ?? 0;
    const harmless = stats.harmless ?? 0;
    const undetected = stats.undetected ?? 0;
    const reputation = attrs.reputation ?? 0;
    const meaningfulName = attrs.meaningful_name ?? '';
    const threatCategory = attrs.popular_threat_category ?? '';

    let severity: Severity;
    let summary: string;

    const total = malicious + suspicious + harmless + undetected;
    const detectionStr = `${malicious}/${total} engines detect this as malicious`;

    if (malicious >= 5) {
      severity = 'critical';
      summary = `VirusTotal: CRITICAL — ${detectionStr}${meaningfulName ? ` (${meaningfulName})` : ''}${threatCategory ? `, threat category: ${threatCategory}` : ''}.`;
    } else if (malicious >= 3) {
      severity = 'high';
      summary = `VirusTotal: HIGH — ${detectionStr}${meaningfulName ? ` (${meaningfulName})` : ''}.`;
    } else if (malicious >= 1) {
      severity = 'medium';
      summary = `VirusTotal: MEDIUM — ${detectionStr}.`;
    } else if (suspicious >= 3) {
      severity = 'medium';
      summary = `VirusTotal: MEDIUM — ${suspicious} engine(s) flagged as suspicious (0 malicious).`;
    } else if (suspicious > 0) {
      severity = 'low';
      summary = `VirusTotal: Low — ${suspicious} engine(s) flagged as suspicious (0 malicious).`;
    } else {
      severity = 'benign';
      summary = `VirusTotal: No detections. ${total} engine(s) analysed, all clean.`;
    }

    const categories = attrs.categories ?? {};
    const lastAnalysisDate = attrs.last_analysis_date
      ? new Date(attrs.last_analysis_date * 1000).toISOString()
      : undefined;

    return makeResult({
      status: 'ok',
      summary,
      severity,
      confidence: total > 10 ? 'high' : total > 0 ? 'medium' : 'low',
      data: {
        malicious,
        suspicious,
        harmless,
        undetected,
        reputation,
        meaningfulName,
        threatCategory,
        categories: Object.values(categories).slice(0, 5),
        lastAnalysisDate: lastAnalysisDate ?? null,
      },
      rawAvailable: true,
      sourceUrl: getSourceUrl(ioc),
      sourceDataTimestamp: lastAnalysisDate,
      lastSeenDate: lastAnalysisDate,
      freshnessLabel: computeFreshness(lastAnalysisDate),
      sourceReliability: 'authoritative',
      keyFacts: [
        { label: 'Detection ratio', value: `${malicious}/${total} engines`, ...(lastAnalysisDate ? { timestamp: lastAnalysisDate } : {}) },
        { label: 'Reputation score', value: String(reputation) },
        ...(meaningfulName ? [{ label: 'Name', value: meaningfulName }] : []),
        ...(threatCategory ? [{ label: 'Threat category', value: threatCategory }] : []),
        ...(suspicious > 0 ? [{ label: 'Suspicious engines', value: String(suspicious) }] : []),
      ],
    });
  } catch (err) {
    clearTimeout(timeout);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({
      status: 'error',
      summary: isTimeout ? 'VirusTotal request timed out.' : 'VirusTotal request failed.',
      errorMessage: err instanceof Error ? err.message : String(err),
    });
  }
}
