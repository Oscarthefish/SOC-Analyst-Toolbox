import type { IocInput, EnrichmentResult, EnrichOptions } from '../types.js';

const PROVIDER_ID = 'crtsh';
const PROVIDER_NAME = 'crt.sh';
const TIMEOUT_MS = 20_000;

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

interface CrtRecord {
  id?: number;
  logged_at?: string;
  not_before?: string;
  not_after?: string;
  common_name?: string;
  name_value?: string;
  issuer_name?: string;
}

function extractCaShortName(issuerName: string | undefined): string {
  if (!issuerName) return 'Unknown';
  const cnMatch = issuerName.match(/CN=([^,]+)/);
  const oMatch = issuerName.match(/O=([^,]+)/);
  return cnMatch?.[1]?.trim() ?? oMatch?.[1]?.trim() ?? issuerName.slice(0, 40);
}

export async function crtsh(
  ioc: IocInput,
  _options: EnrichOptions,
): Promise<EnrichmentResult> {
  if (ioc.type !== 'domain') {
    return makeResult({
      status: 'unsupported_ioc',
      summary: `crt.sh does not support IOC type: ${ioc.type} (supports: domain).`,
    });
  }

  const hostname = ioc.normalised;
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(hostname)}&output=json`;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: 'application/json', 'User-Agent': 'SOC-Analyst-Toolbox/1.0' },
    });
    clearTimeout(timeout);

    if (res.status === 429) {
      return makeResult({
        status: 'rate_limited',
        summary: 'crt.sh rate limit reached. Try again in a few minutes.',
      });
    }
    if (!res.ok) {
      return makeResult({
        status: 'error',
        summary: `crt.sh returned HTTP ${res.status}.`,
        errorMessage: `HTTP ${res.status}`,
      });
    }

    const raw = await res.text();
    if (!raw || raw.trim() === '') {
      return makeResult({
        status: 'ok',
        summary: `crt.sh: No certificate records found for ${hostname}.`,
        severity: 'unknown',
        confidence: 'low',
        data: { certCount: 0 },
        relatedDomains: [],
        sourceReliability: 'passive-infra',
        sourceUrl: `https://crt.sh/?q=%25.${hostname}`,
        keyFacts: [{ label: 'Certificates', value: '0' }],
      });
    }

    const certs = JSON.parse(raw) as CrtRecord[];
    if (!Array.isArray(certs) || certs.length === 0) {
      return makeResult({
        status: 'ok',
        summary: `crt.sh: No certificate records found for ${hostname}.`,
        severity: 'unknown',
        confidence: 'low',
        data: { certCount: 0 },
        relatedDomains: [],
        sourceReliability: 'passive-infra',
        sourceUrl: `https://crt.sh/?q=%25.${hostname}`,
        keyFacts: [{ label: 'Certificates', value: '0' }],
      });
    }

    // Sort by most recent, cap at 200 to avoid huge processing on popular domains
    const recent = certs
      .filter(c => c.logged_at)
      .sort((a, b) => (b.logged_at ?? '').localeCompare(a.logged_at ?? ''))
      .slice(0, 200);

    const allNames = new Set<string>();
    const wildcardNames = new Set<string>();
    const issuers = new Map<string, number>();

    for (const cert of recent) {
      const names = (cert.name_value ?? '')
        .split('\n')
        .map(s => s.trim())
        .filter(Boolean);
      for (const name of names) {
        if (name.startsWith('*.')) {
          wildcardNames.add(name);
        } else {
          allNames.add(name);
        }
      }
      if (cert.common_name && !cert.common_name.startsWith('*.')) {
        allNames.add(cert.common_name);
      }
      const ca = extractCaShortName(cert.issuer_name);
      issuers.set(ca, (issuers.get(ca) ?? 0) + 1);
    }

    // Remove the queried domain itself — pivot is for *related* domains
    allNames.delete(hostname);

    // Subdomains: names that are directly beneath the queried hostname
    const subdomains = Array.from(allNames)
      .filter(n => n.endsWith(`.${hostname}`))
      .sort();

    // Related domains: everything else (SAN names from other orgs on a shared cert, etc.)
    const relatedDomains = Array.from(allNames)
      .filter(n => !n.endsWith(`.${hostname}`))
      .slice(0, 25);

    const topIssuer = [...issuers.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? 'Unknown';
    const latestDate = recent[0]?.logged_at?.split('T')[0];
    const certCount = certs.length;

    return makeResult({
      status: 'ok',
      summary: `crt.sh: ${certCount} cert(s) found for ${hostname}. ${subdomains.length} subdomain(s) identified via certificate SANs.`,
      severity: 'unknown',
      confidence: subdomains.length > 0 ? 'medium' : 'low',
      data: {
        certCount,
        subdomainCount: subdomains.length,
        subdomains: subdomains.slice(0, 100),
        relatedDomainCount: relatedDomains.length,
        wildcardCount: wildcardNames.size,
        topIssuer,
      },
      relatedDomains,
      sourceReliability: 'passive-infra',
      sourceUrl: `https://crt.sh/?q=%25.${hostname}`,
      keyFacts: [
        { label: 'Certificates', value: String(certCount) },
        { label: 'Subdomains (SANs)', value: String(subdomains.length) },
        { label: 'Wildcard certs', value: String(wildcardNames.size) },
        { label: 'Top issuer', value: topIssuer },
        ...(latestDate ? [{ label: 'Latest cert', value: latestDate }] : []),
      ],
    });
  } catch (err) {
    clearTimeout(timeout);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({
      status: 'error',
      summary: isTimeout ? 'crt.sh request timed out.' : 'crt.sh request failed.',
      errorMessage: err instanceof Error ? err.message : String(err),
    });
  }
}
