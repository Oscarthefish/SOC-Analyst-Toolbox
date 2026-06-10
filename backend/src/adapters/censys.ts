import fetch from 'node-fetch';
import type { IocInput, EnrichmentResult, EnrichOptions, Severity } from '../types.js';
import { config } from '../config.js';
import { markRateLimited } from '../rateLimit.js';

const PROVIDER_ID = 'censys';
const PROVIDER_NAME = 'Censys';
const TIMEOUT_MS = 10_000;
const BASE_URL = 'https://api.platform.censys.io/v3/global/asset/host';
const ACCEPT = 'application/vnd.censys.api.v3.host.v1+json';

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

interface CensysV3Service {
  port?: number;
  protocol?: string;
  transport_protocol?: string;
}

interface CensysV3Response {
  result?: {
    resource?: {
      ip?: string;
      services?: CensysV3Service[];
      autonomous_system?: {
        asn?: number;
        name?: string;
        bgp_prefix?: string;
        country_code?: string;
      };
      location?: {
        country?: string;
        country_code?: string;
        city?: string;
      };
    };
  };
  error?: { code?: number; message?: string; status?: string };
  code?: number;
  status?: string;
}

export async function censys(
  ioc: IocInput,
  _options: EnrichOptions,
): Promise<EnrichmentResult> {
  if (ioc.type !== 'ipv4' && ioc.type !== 'ipv6') {
    return makeResult({
      status: 'unsupported_ioc',
      summary: `Censys host lookup only supports IPv4/IPv6 addresses (got: ${ioc.type}).`,
    });
  }

  const { apiToken } = config.censys;
  if (!apiToken) {
    return makeResult({
      status: 'missing_key',
      summary: 'Censys API token is not configured.',
    });
  }

  const url = `${BASE_URL}/${encodeURIComponent(ioc.normalised)}`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      headers: {
        Authorization: `Bearer ${apiToken}`,
        Accept: ACCEPT,
      },
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (res.status === 429) {
      markRateLimited(PROVIDER_ID);
      return makeResult({
        status: 'rate_limited',
        summary: 'Censys rate limit reached. Try again later.',
      });
    }

    if (res.status === 401 || res.status === 403) {
      return makeResult({
        status: 'error',
        summary: `Censys authentication failed (HTTP ${res.status}). Check your CENSYS_API_TOKEN.`,
        errorMessage: `HTTP ${res.status}`,
      });
    }

    if (res.status === 404) {
      return makeResult({
        status: 'ok',
        summary: 'Censys has no data for this IP address.',
        severity: 'unknown',
        confidence: 'low',
        data: { inDataset: false },
        sourceUrl: `https://search.censys.io/hosts/${ioc.normalised}`,
      });
    }

    if (!res.ok) {
      return makeResult({
        status: 'error',
        summary: `Censys returned HTTP ${res.status}.`,
        errorMessage: `HTTP ${res.status}`,
      });
    }

    const body = (await res.json()) as CensysV3Response;

    if (body.error) {
      return makeResult({
        status: 'error',
        summary: `Censys error: ${body.error.message ?? body.error.status ?? 'unknown'}.`,
        errorMessage: body.error.message ?? String(body.error.code),
      });
    }

    const resource = body.result?.resource;
    if (!resource) {
      return makeResult({
        status: 'error',
        summary: 'Censys returned an unexpected response format.',
        errorMessage: 'No result.resource in response',
      });
    }

    const services = resource.services ?? [];
    const as = resource.autonomous_system ?? {};
    const location = resource.location ?? {};

    const ports = services.map(s => s.port).filter((p): p is number => p !== undefined);
    const serviceNames = services
      .map(s => `${s.port}/${s.transport_protocol?.toLowerCase() ?? 'tcp'} (${s.protocol ?? 'unknown'})`)
      .slice(0, 10);

    const HIGH_RISK_PORTS = new Set([3389, 445, 23, 5900, 1433, 3306, 5432]);
    const hasHighRiskPorts = ports.some(p => HIGH_RISK_PORTS.has(p));

    let severity: Severity;
    let summary: string;

    if (hasHighRiskPorts) {
      const risky = ports.filter(p => HIGH_RISK_PORTS.has(p));
      severity = 'medium';
      summary = `Censys: High-risk ports detected (${risky.join(', ')}) on ASN ${as.asn ?? 'unknown'} (${as.name ?? 'unknown'}), ${location.country ?? 'unknown'}. NOTE: Exposure data does not prove compromise.`;
    } else if (ports.length > 0) {
      severity = 'low';
      summary = `Censys: ${ports.length} service(s) found. Org: ${as.name ?? 'unknown'} (ASN ${as.asn ?? 'unknown'}), ${location.country ?? 'unknown'}. NOTE: This is exposure context only.`;
    } else {
      severity = 'unknown';
      summary = `Censys: No services found. Org: ${as.name ?? 'unknown'}.`;
    }

    return makeResult({
      status: 'ok',
      summary,
      severity,
      confidence: ports.length > 0 ? 'high' : 'medium',
      data: {
        ports,
        services: serviceNames,
        asn: as.asn,
        asnName: as.name,
        bgpPrefix: as.bgp_prefix,
        country: location.country,
        city: location.city,
      },
      rawAvailable: true,
      sourceUrl: `https://search.censys.io/hosts/${ioc.normalised}`,
      sourceReliability: 'passive-infra' as const,
      keyFacts: [
        ...(as.name ? [{ label: 'Org', value: as.name }] : []),
        ...(as.asn ? [{ label: 'ASN', value: `AS${as.asn}` }] : []),
        ...(location.country ? [{ label: 'Country', value: location.country + (location.city ? `, ${location.city}` : '') }] : []),
        { label: 'Open ports', value: ports.length > 0 ? `${ports.length} (${ports.slice(0, 5).join(', ')}${ports.length > 5 ? '…' : ''})` : 'none' },
      ],
    });
  } catch (err) {
    clearTimeout(timeout);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({
      status: 'error',
      summary: isTimeout ? 'Censys request timed out.' : 'Censys request failed.',
      errorMessage: err instanceof Error ? err.message : String(err),
    });
  }
}
