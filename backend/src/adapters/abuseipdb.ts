import type { IocInput, EnrichmentResult, EnrichOptions, Severity } from '../types.js';
import { config } from '../config.js';
import { markRateLimited } from '../rateLimit.js';
import { computeFreshness } from '../lib/freshness.js';
import { resultFactory } from '../lib/result.js';

const PROVIDER_ID = 'abuseipdb';
const PROVIDER_NAME = 'AbuseIPDB';
const TIMEOUT_MS = 10_000;
const makeResult = resultFactory(PROVIDER_ID, PROVIDER_NAME);

interface AbuseIpDbResponse {
  data?: {
    ipAddress?: string;
    abuseConfidenceScore?: number;
    totalReports?: number;
    countryCode?: string;
    isp?: string;
    domain?: string;
    usageType?: string;
    lastReportedAt?: string;
    isPublic?: boolean;
    isWhitelisted?: boolean;
  };
  errors?: { detail?: string }[];
}

export async function abuseipdb(
  ioc: IocInput,
  _options: EnrichOptions,
): Promise<EnrichmentResult> {
  if (ioc.type !== 'ipv4' && ioc.type !== 'ipv6') {
    return makeResult({
      status: 'unsupported_ioc',
      summary: `AbuseIPDB does not support IOC type: ${ioc.type}.`,
    });
  }

  const apiKey = config.abuseipdb.apiKey;
  if (!apiKey) {
    return makeResult({
      status: 'missing_key',
      summary: 'AbuseIPDB API key is not configured.',
    });
  }

  const params = new URLSearchParams({
    ipAddress: ioc.normalised,
    maxAgeInDays: '90',
    verbose: 'false',
  });

  const url = `https://api.abuseipdb.com/api/v2/check?${params.toString()}`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      headers: {
        Key: apiKey,
        Accept: 'application/json',
      },
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (res.status === 429) {
      markRateLimited(PROVIDER_ID);
      return makeResult({
        status: 'rate_limited',
        summary: 'AbuseIPDB rate limit reached. Try again in 60 seconds.',
      });
    }

    if (!res.ok) {
      return makeResult({
        status: 'error',
        summary: `AbuseIPDB returned HTTP ${res.status}.`,
        errorMessage: `HTTP ${res.status}`,
      });
    }

    const body = (await res.json()) as AbuseIpDbResponse;
    const d = body.data;

    if (!d) {
      return makeResult({
        status: 'error',
        summary: 'AbuseIPDB returned an unexpected response format.',
        errorMessage: 'No data field in response',
      });
    }

    const score = d.abuseConfidenceScore ?? 0;
    const totalReports = d.totalReports ?? 0;
    const countryCode = d.countryCode ?? '';
    const isp = d.isp ?? '';
    const domain = d.domain ?? '';
    const usageType = d.usageType ?? '';
    const lastReportedAt = d.lastReportedAt ?? '';
    const isWhitelisted = d.isWhitelisted ?? false;

    let severity: Severity;
    let summary: string;

    const usageSuffix = usageType ? ` Usage type: ${usageType}.` : '';

    if (isWhitelisted) {
      severity = 'benign';
      summary = `AbuseIPDB: IP is whitelisted (score: ${score}). ISP: ${isp || 'unknown'}, Country: ${countryCode || 'unknown'}.${usageSuffix}`;
    } else if (score >= 75) {
      severity = 'high';
      summary = `AbuseIPDB: HIGH abuse confidence (${score}%) with ${totalReports} report(s). ISP: ${isp || 'unknown'}, Country: ${countryCode || 'unknown'}. Last reported: ${lastReportedAt || 'unknown'}.${usageSuffix}`;
    } else if (score >= 25) {
      severity = 'medium';
      summary = `AbuseIPDB: MEDIUM abuse confidence (${score}%) with ${totalReports} report(s). ISP: ${isp || 'unknown'}, Country: ${countryCode || 'unknown'}.${usageSuffix}`;
    } else if (score > 0) {
      severity = 'low';
      summary = `AbuseIPDB: Low abuse confidence (${score}%) with ${totalReports} report(s). ISP: ${isp || 'unknown'}, Country: ${countryCode || 'unknown'}.${usageSuffix}`;
    } else {
      severity = 'benign';
      summary = `AbuseIPDB: No abuse reports found (score: 0). ISP: ${isp || 'unknown'}, Country: ${countryCode || 'unknown'}.${usageSuffix}`;
    }

    const lastSeenDate = lastReportedAt || undefined;

    return makeResult({
      status: 'ok',
      summary,
      severity,
      confidence: score > 0 ? 'high' : 'medium',
      data: {
        abuseConfidenceScore: score,
        totalReports,
        countryCode,
        isp,
        domain,
        usageType,
        lastReportedAt,
        isWhitelisted,
      },
      rawAvailable: true,
      sourceUrl: `https://www.abuseipdb.com/check/${ioc.normalised}`,
      lastSeenDate,
      freshnessLabel: computeFreshness(lastSeenDate),
      sourceReliability: 'community',
      keyFacts: [
        { label: 'Abuse score', value: `${score}%` },
        { label: 'Report count', value: String(totalReports) },
        ...(isp ? [{ label: 'ISP', value: isp }] : []),
        ...(usageType ? [{ label: 'Usage type', value: usageType }] : []),
        ...(countryCode ? [{ label: 'Country', value: countryCode }] : []),
        ...(lastReportedAt ? [{ label: 'Last report', value: lastReportedAt }] : []),
        ...(isWhitelisted ? [{ label: 'Whitelisted', value: 'yes' }] : []),
      ],
    });
  } catch (err) {
    clearTimeout(timeout);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({
      status: 'error',
      summary: isTimeout ? 'AbuseIPDB request timed out.' : 'AbuseIPDB request failed.',
      errorMessage: err instanceof Error ? err.message : String(err),
    });
  }
}
