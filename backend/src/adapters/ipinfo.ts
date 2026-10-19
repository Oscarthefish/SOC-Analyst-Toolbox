import type { IocInput, EnrichmentResult, EnrichOptions, Confidence } from '../types.js';
import { config } from '../config.js';
import { markRateLimited } from '../rateLimit.js';
import { resultFactory } from '../lib/result.js';

const PROVIDER_ID = 'ipinfo';
const PROVIDER_NAME = 'IPinfo';
const TIMEOUT_MS = 10_000;
const makeResult = resultFactory(PROVIDER_ID, PROVIDER_NAME);

interface IpInfoResponse {
  ip?: string;
  asn?: string;
  as_name?: string;
  as_domain?: string;
  country_code?: string;
  country?: string;
  continent_code?: string;
  continent?: string;
  error?: {
    status?: number;
    title?: string;
    message?: string;
  };
}

export async function ipinfo(
  ioc: IocInput,
  _options: EnrichOptions,
): Promise<EnrichmentResult> {
  if (ioc.type !== 'ipv4' && ioc.type !== 'ipv6') {
    return makeResult({
      status: 'unsupported_ioc',
      summary: `IPinfo does not support IOC type: ${ioc.type}.`,
    });
  }

  const token = config.ipinfo.token;
  if (!token) {
    return makeResult({
      status: 'missing_key',
      summary: 'IPinfo token is not configured.',
    });
  }

  const url = `https://api.ipinfo.io/lite/${encodeURIComponent(ioc.normalised)}`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { Authorization: `Bearer ${token}` },
    });
    clearTimeout(timeout);

    if (res.status === 429) {
      markRateLimited(PROVIDER_ID);
      return makeResult({
        status: 'rate_limited',
        summary: 'IPinfo rate limit reached. Try again in 60 seconds.',
      });
    }

    if (!res.ok) {
      return makeResult({
        status: 'error',
        summary: `IPinfo returned HTTP ${res.status}.`,
        errorMessage: `HTTP ${res.status}`,
      });
    }

    const body = (await res.json()) as IpInfoResponse;

    if (body.error) {
      return makeResult({
        status: 'error',
        summary: `IPinfo error: ${body.error.title ?? body.error.message ?? 'unknown'}.`,
        errorMessage: body.error.title ?? body.error.message ?? 'Unknown error',
      });
    }

    const asn = body.asn ?? '';
    const asName = body.as_name ?? '';
    const asDomain = body.as_domain ?? '';
    const country = body.country ?? '';
    const countryCode = body.country_code ?? '';
    const continent = body.continent ?? '';

    const summary = `IPinfo: ${asName || 'unknown org'} (${asn}), ${country || 'unknown country'}${continent ? `, ${continent}` : ''}.`;

    const confidence: Confidence = asName ? 'medium' : 'low';

    return makeResult({
      status: 'ok',
      summary,
      severity: 'unknown',
      confidence,
      data: {
        ip: body.ip,
        asn,
        asName,
        asDomain,
        country,
        countryCode,
        continent,
      },
      rawAvailable: true,
      sourceUrl: `https://ipinfo.io/${ioc.normalised}`,
      sourceReliability: 'passive-infra' as const,
      keyFacts: [
        ...(asName ? [{ label: 'Org', value: asName }] : []),
        ...(asn ? [{ label: 'ASN', value: asn }] : []),
        ...(country ? [{ label: 'Country', value: country }] : []),
        ...(continent ? [{ label: 'Continent', value: continent }] : []),
      ],
    });
  } catch (err) {
    clearTimeout(timeout);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({
      status: 'error',
      summary: isTimeout ? 'IPinfo request timed out.' : 'IPinfo request failed.',
      errorMessage: err instanceof Error ? err.message : String(err),
    });
  }
}
