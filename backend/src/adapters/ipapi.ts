import type { IocInput, EnrichmentResult, EnrichOptions, Severity } from '../types.js';
import { markRateLimited } from '../rateLimit.js';
import { config } from '../config.js';
import { resultFactory } from '../lib/result.js';

const PROVIDER_ID = 'ipapi';
const PROVIDER_NAME = 'ip-api.com';
const TIMEOUT_MS = 8_000;
const makeResult = resultFactory(PROVIDER_ID, PROVIDER_NAME);

// Free tier: 45 req/min and plain HTTP only, so the IP crosses the network unencrypted.
// With IPAPI_KEY the paid HTTPS endpoint is used; the free endpoint needs an explicit
// IPAPI_ALLOW_HTTP=true. Returns proxy/hosting booleans.
const FIELDS = 'status,message,country,countryCode,regionName,city,isp,org,as,proxy,hosting,query';

interface IpApiResponse {
  status?: string;
  message?: string;
  country?: string;
  countryCode?: string;
  regionName?: string;
  city?: string;
  isp?: string;
  org?: string;
  as?: string;
  proxy?: boolean;
  hosting?: boolean;
  query?: string;
}

export async function ipapi(
  ioc: IocInput,
  _options: EnrichOptions,
): Promise<EnrichmentResult> {
  if (ioc.type !== 'ipv4' && ioc.type !== 'ipv6') {
    return makeResult({
      status: 'unsupported_ioc',
      summary: `ip-api.com does not support IOC type: ${ioc.type}.`,
    });
  }

  const apiKey = config.ipapi.apiKey;
  const allowHttp = process.env.IPAPI_ALLOW_HTTP === 'true';
  if (!apiKey && !allowHttp) {
    return makeResult({
      status: 'missing_key',
      summary: 'ip-api.com is off: its free tier is plain HTTP. Set IPAPI_KEY (HTTPS) or IPAPI_ALLOW_HTTP=true.',
    });
  }
  const query = `${encodeURIComponent(ioc.normalised)}?fields=${FIELDS}`;
  const url = apiKey
    ? `https://pro.ip-api.com/json/${query}&key=${encodeURIComponent(apiKey)}`
    : `http://ip-api.com/json/${query}`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(url, { signal: controller.signal });
    clearTimeout(timeout);

    if (res.status === 429) {
      markRateLimited(PROVIDER_ID);
      return makeResult({
        status: 'rate_limited',
        summary: 'ip-api.com rate limit reached (45 req/min on free tier). Try again shortly.',
      });
    }

    if (!res.ok) {
      return makeResult({
        status: 'error',
        summary: `ip-api.com returned HTTP ${res.status}.`,
        errorMessage: `HTTP ${res.status}`,
      });
    }

    const body = (await res.json()) as IpApiResponse;

    if (body.status === 'fail') {
      return makeResult({
        status: 'error',
        summary: `ip-api.com: ${body.message ?? 'lookup failed'}.`,
        errorMessage: body.message ?? 'status=fail',
      });
    }

    const isProxy   = body.proxy   ?? false;
    const isHosting = body.hosting ?? false;
    const isp       = body.isp     ?? '';
    const org       = body.org     ?? '';
    const asn       = body.as      ?? '';
    const country   = body.country ?? '';
    const city      = body.city    ?? '';

    // Build a concise classification label
    const flags: string[] = [];
    if (isProxy)   flags.push('VPN/Proxy/Tor');
    if (isHosting) flags.push('Hosting/Datacenter');

    const classification = flags.length > 0 ? flags.join(' + ') : 'Residential/ISP';

    let severity: Severity;
    if (isProxy) {
      severity = 'medium'; // proxy alone warrants medium — attacker may be hiding behind it
    } else if (isHosting) {
      severity = 'low'; // datacenter IPs are common but worth noting
    } else {
      severity = 'benign';
    }

    const locationParts = [city, country].filter(Boolean).join(', ');
    const orgDisplay    = org || isp;

    const summary = `ip-api.com: ${classification}${orgDisplay ? ` — ${orgDisplay}` : ''}${asn ? ` (${asn})` : ''}${locationParts ? `, ${locationParts}` : ''}.${isProxy ? ' IP is flagged as a VPN, proxy, or Tor exit node.' : ''}`;

    return makeResult({
      status: 'ok',
      summary,
      severity,
      confidence: 'medium',
      data: {
        isProxy,
        isHosting,
        classification,
        isp,
        org,
        asn,
        country,
        countryCode: body.countryCode,
        regionName: body.regionName,
        city,
      },
      rawAvailable: true,
      sourceUrl: `https://ip-api.com/#${ioc.normalised}`,
      sourceReliability: 'passive-infra',
      keyFacts: [
        { label: 'Usage type', value: classification },
        ...(asn ? [{ label: 'ASN', value: asn }] : []),
        ...(org || isp ? [{ label: 'ISP / Org', value: org || isp }] : []),
        ...(locationParts ? [{ label: 'Location', value: locationParts }] : []),
        { label: 'VPN / Proxy', value: isProxy ? 'Yes' : 'No' },
        { label: 'Datacenter / Hosting', value: isHosting ? 'Yes' : 'No' },
      ],
    });
  } catch (err) {
    clearTimeout(timeout);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({
      status: 'error',
      summary: isTimeout ? 'ip-api.com request timed out.' : 'ip-api.com request failed.',
      errorMessage: err instanceof Error ? err.message : String(err),
    });
  }
}
