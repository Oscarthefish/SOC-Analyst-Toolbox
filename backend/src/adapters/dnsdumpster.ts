import type { IocInput, EnrichmentResult, EnrichOptions } from '../types.js';
import { config } from '../config.js';
import { resultFactory } from '../lib/result.js';

const PROVIDER_ID = 'dnsdumpster';
const PROVIDER_NAME = 'DNSDumpster';
const BASE_URL = 'https://api.dnsdumpster.com';
const TIMEOUT_MS = 15_000;
const makeResult = resultFactory(PROVIDER_ID, PROVIDER_NAME);

interface DnsDumpsterRecord {
  host?: string;
  ip?: string;
  as?: string;
  asn?: string;
  country?: string;
  provider?: string;
  exchange?: string;
  priority?: number;
  name?: string;
  value?: string;
}

interface DnsDumpsterResponse {
  a?: DnsDumpsterRecord[];
  aaaa?: DnsDumpsterRecord[];
  cname?: DnsDumpsterRecord[];
  mx?: DnsDumpsterRecord[];
  ns?: DnsDumpsterRecord[];
  txt?: DnsDumpsterRecord[];
  soa?: DnsDumpsterRecord[];
  total?: number;
}

export async function dnsdumpster(
  ioc: IocInput,
  _options: EnrichOptions,
): Promise<EnrichmentResult> {
  const apiKey = config.dnsdumpster?.apiKey;
  if (!apiKey) {
    return makeResult({
      status: 'missing_key',
      summary: 'DNSDumpster API key not configured.',
      errorMessage: 'Set DNSDUMPSTER_API_KEY in backend/.env',
    });
  }

  let domain: string;
  if (ioc.type === 'domain') {
    domain = ioc.normalised;
  } else if (ioc.type === 'url') {
    try {
      domain = new URL(ioc.normalised).hostname.replace(/^www\./, '');
    } catch {
      domain = ioc.normalised;
    }
  } else {
    return makeResult({
      status: 'unsupported_ioc',
      summary: `DNSDumpster does not support IOC type: ${ioc.type} (supports: domain, url).`,
    });
  }

  const url = `${BASE_URL}/domain/${encodeURIComponent(domain)}`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        'X-API-Key': apiKey,
        'User-Agent': 'SOC-Analyst-Toolbox/1.0',
        'Accept': 'application/json',
      },
    });
    clearTimeout(timeout);

    if (res.status === 401 || res.status === 403) {
      return makeResult({
        status: 'missing_key',
        summary: 'DNSDumpster API key is invalid or unauthorised.',
        errorMessage: `HTTP ${res.status}`,
      });
    }
    if (res.status === 429) {
      return makeResult({
        status: 'rate_limited',
        summary: 'DNSDumpster rate limit reached (1 req/2s). Try again shortly.',
      });
    }
    if (!res.ok) {
      return makeResult({
        status: 'error',
        summary: `DNSDumpster returned HTTP ${res.status}.`,
        errorMessage: `HTTP ${res.status}`,
      });
    }

    const data = (await res.json()) as DnsDumpsterResponse;

    const aRecords   = data.a     ?? [];
    const mxRecords  = data.mx    ?? [];
    const nsRecords  = data.ns    ?? [];
    const txtRecords = data.txt   ?? [];
    const cnameRecords = data.cname ?? [];

    const resolvedIps = aRecords
      .map(r => r.ip)
      .filter((ip): ip is string => Boolean(ip));

    const subdomains = [
      ...aRecords.map(r => r.host),
      ...cnameRecords.map(r => r.host),
    ]
      .filter((h): h is string => Boolean(h) && h !== domain && h !== `www.${domain}`)
      .filter((v, i, a) => a.indexOf(v) === i)
      .slice(0, 20);

    const mailServers = mxRecords
      .map(r => r.exchange ?? r.host)
      .filter((h): h is string => Boolean(h))
      .slice(0, 5);

    const nameServers = nsRecords
      .map(r => r.host ?? r.name)
      .filter((h): h is string => Boolean(h))
      .filter((v, i, a) => a.indexOf(v) === i)
      .slice(0, 6);

    const txtValues = txtRecords.map(r => r.value ?? '').filter(Boolean);
    const spf   = txtValues.find(v => v.toLowerCase().startsWith('v=spf'));
    const dmarc = txtValues.find(v => v.toLowerCase().includes('v=dmarc'));

    const hostCount = aRecords.length + cnameRecords.length;

    if (hostCount === 0 && nsRecords.length === 0) {
      return makeResult({
        status: 'ok',
        summary: `DNSDumpster: No DNS records found for ${domain}.`,
        severity: 'unknown',
        confidence: 'low',
        data: { hostCount: 0 },
        sourceReliability: 'passive-infra',
        sourceUrl: 'https://dnsdumpster.com/',
        keyFacts: [{ label: 'Records', value: 'None found' }],
      });
    }

    const keyFacts = [];
    if (aRecords.length > 0) {
      keyFacts.push({ label: 'A records', value: String(aRecords.length) });
    }
    if (resolvedIps.length > 0) {
      const preview = resolvedIps.slice(0, 4).join(', ') + (resolvedIps.length > 4 ? ` +${resolvedIps.length - 4} more` : '');
      keyFacts.push({ label: 'IP addresses', value: preview });
    }
    if (subdomains.length > 0) {
      const total = data.total;
      keyFacts.push({ label: 'Subdomains', value: total && total > subdomains.length ? `${subdomains.length} of ${total}` : String(subdomains.length) });
    }
    if (mailServers.length > 0) {
      keyFacts.push({ label: 'MX servers', value: mailServers.join(', ') });
    }
    if (nameServers.length > 0) {
      keyFacts.push({ label: 'Name servers', value: nameServers.join(', ') });
    }
    if (spf)   keyFacts.push({ label: 'SPF',   value: spf.slice(0, 100) });
    if (dmarc) keyFacts.push({ label: 'DMARC', value: dmarc.slice(0, 100) });

    return makeResult({
      status: 'ok',
      summary: `DNSDumpster: ${hostCount} host(s), ${mailServers.length} MX, ${nameServers.length} NS${subdomains.length > 0 ? `, ${subdomains.length} subdomain(s)` : ''} for ${domain}.`,
      severity: 'unknown',
      confidence: 'high',
      data: {
        hostCount,
        aCount:      aRecords.length,
        mxCount:     mxRecords.length,
        nsCount:     nsRecords.length,
        txtCount:    txtRecords.length,
        cnameCount:  cnameRecords.length,
        subdomainCount: subdomains.length,
      },
      resolvedIps: resolvedIps.slice(0, 10),
      relatedDomains: subdomains,
      sourceReliability: 'passive-infra',
      sourceUrl: 'https://dnsdumpster.com/',
      keyFacts,
    });
  } catch (err) {
    clearTimeout(timeout);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({
      status: 'error',
      summary: isTimeout ? 'DNSDumpster request timed out.' : 'DNSDumpster request failed.',
      errorMessage: err instanceof Error ? err.message : String(err),
    });
  }
}
