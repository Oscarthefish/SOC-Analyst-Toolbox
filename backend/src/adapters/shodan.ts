import fetch from 'node-fetch';
import type { IocInput, EnrichmentResult, EnrichOptions, Severity } from '../types.js';
import { config } from '../config.js';
import { markRateLimited } from '../rateLimit.js';
import { computeFreshness } from '../lib/freshness.js';

const PROVIDER_ID = 'shodan';
const PROVIDER_NAME = 'Shodan';
const TIMEOUT_MS = 10_000;

// Ports commonly associated with high-risk exposure
const HIGH_RISK_PORTS = new Set([3389, 445, 23, 22, 5900, 1433, 3306, 5432]);
const MEDIUM_RISK_PORTS = new Set([80, 443, 8080, 8443, 8888, 9200, 6379, 27017]);

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

interface ShodanResponse {
  ip_str?: string;
  org?: string;
  isp?: string;
  asn?: string;
  ports?: number[];
  hostnames?: string[];
  domains?: string[];
  last_update?: string;
  country_name?: string;
  vulns?: Record<string, unknown>;
  error?: string;
}

export async function shodan(
  ioc: IocInput,
  _options: EnrichOptions,
): Promise<EnrichmentResult> {
  if (ioc.type !== 'ipv4') {
    return makeResult({
      status: 'unsupported_ioc',
      summary: `Shodan host lookup only supports IPv4 addresses (got: ${ioc.type}).`,
    });
  }

  const apiKey = config.shodan.apiKey;
  if (!apiKey) {
    return makeResult({
      status: 'missing_key',
      summary: 'Shodan API key is not configured.',
    });
  }

  const url = `https://api.shodan.io/shodan/host/${encodeURIComponent(ioc.normalised)}?key=${apiKey}`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(url, { signal: controller.signal });
    clearTimeout(timeout);

    if (res.status === 429) {
      markRateLimited(PROVIDER_ID);
      return makeResult({
        status: 'rate_limited',
        summary: 'Shodan rate limit reached. Try again in 60 seconds.',
      });
    }

    if (res.status === 404) {
      return makeResult({
        status: 'ok',
        summary: 'Shodan has no data for this IP address.',
        severity: 'unknown',
        confidence: 'low',
        data: { inDataset: false },
        sourceUrl: `https://www.shodan.io/host/${ioc.normalised}`,
      });
    }

    if (!res.ok) {
      return makeResult({
        status: 'error',
        summary: `Shodan returned HTTP ${res.status}.`,
        errorMessage: `HTTP ${res.status}`,
      });
    }

    const body = (await res.json()) as ShodanResponse;

    if (body.error) {
      return makeResult({
        status: 'error',
        summary: `Shodan error: ${body.error}.`,
        errorMessage: body.error,
      });
    }

    const org = body.org ?? '';
    const isp = body.isp ?? '';
    const asn = body.asn ?? '';
    const ports = body.ports ?? [];
    const hostnames = body.hostnames ?? [];
    const country = body.country_name ?? '';
    const lastUpdate = body.last_update ?? '';
    const vulns = body.vulns ?? {};
    const vulnCount = Object.keys(vulns).length;
    const vulnList = Object.keys(vulns).slice(0, 5);

    let severity: Severity;
    let summary: string;

    const hasHighRiskPorts = ports.some(p => HIGH_RISK_PORTS.has(p));
    const hasMediumRiskPorts = ports.some(p => MEDIUM_RISK_PORTS.has(p));

    if (vulnCount > 0) {
      severity = vulnCount >= 3 ? 'high' : 'medium';
      summary = `Shodan: ${ports.length} open port(s) on ${org || isp || 'unknown org'} (ASN: ${asn || 'unknown'}), country: ${country || 'unknown'}. ${vulnCount} CVE(s) noted${vulnList.length ? `: ${vulnList.join(', ')}` : ''}. NOTE: Shodan exposure data does not prove compromise.`;
    } else if (hasHighRiskPorts) {
      severity = 'medium';
      const risky = ports.filter(p => HIGH_RISK_PORTS.has(p));
      summary = `Shodan: High-risk ports exposed (${risky.join(', ')}) on ${org || isp || 'unknown org'} (ASN: ${asn || 'unknown'}). NOTE: Exposure does not prove compromise.`;
    } else if (ports.length > 0) {
      severity = 'low';
      const notable = hasMediumRiskPorts ? ports.filter(p => MEDIUM_RISK_PORTS.has(p)) : ports.slice(0, 10);
      summary = `Shodan: ${ports.length} port(s) open (${notable.join(', ')}${ports.length > 10 ? '...' : ''}). Org: ${org || isp || 'unknown'}. NOTE: This is exposure context only, not a verdict.`;
    } else {
      severity = 'unknown';
      summary = `Shodan: No open ports found for this IP. Org: ${org || 'unknown'}.`;
    }

    const lastUpdateIso = lastUpdate ? new Date(lastUpdate).toISOString() : undefined;
    const topPorts = ports.slice(0, 10).join(', ');

    return makeResult({
      status: 'ok',
      summary,
      severity,
      confidence: ports.length > 0 ? 'high' : 'medium',
      data: {
        org,
        isp,
        asn,
        ports: ports.slice(0, 20),
        totalPorts: ports.length,
        hostnames: hostnames.slice(0, 5),
        country,
        lastUpdate,
        vulnCount,
        vulns: vulnList,
      },
      rawAvailable: true,
      sourceUrl: `https://www.shodan.io/host/${ioc.normalised}`,
      lastSeenDate: lastUpdateIso,
      freshnessLabel: computeFreshness(lastUpdateIso),
      sourceReliability: 'passive-infra',
      keyFacts: [
        ...(org ? [{ label: 'Org', value: org }] : isp ? [{ label: 'ISP', value: isp }] : []),
        ...(asn ? [{ label: 'ASN', value: asn }] : []),
        ...(country ? [{ label: 'Country', value: country }] : []),
        { label: 'Open ports', value: ports.length > 0 ? `${ports.length} (${topPorts}${ports.length > 10 ? '…' : ''})` : 'none' },
        ...(vulnCount > 0 ? [{ label: 'CVEs (Shodan)', value: vulnList.join(', ') }] : []),
        ...(hostnames.length > 0 ? [{ label: 'Hostnames', value: hostnames.slice(0, 3).join(', ') }] : []),
        ...(lastUpdate ? [{ label: 'Last scanned', value: lastUpdate.split('T')[0] }] : []),
      ],
    });
  } catch (err) {
    clearTimeout(timeout);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({
      status: 'error',
      summary: isTimeout ? 'Shodan request timed out.' : 'Shodan request failed.',
      errorMessage: err instanceof Error ? err.message : String(err),
    });
  }
}
