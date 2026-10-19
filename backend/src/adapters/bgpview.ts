import type { IocInput, EnrichmentResult, EnrichOptions } from '../types.js';

const PROVIDER_ID = 'bgpview';
const PROVIDER_NAME = 'RIPE Stat';
const TIMEOUT_MS = 10_000;
const BASE = 'https://stat.ripe.net/data';

function now(): string { return new Date().toISOString(); }

function makeResult(overrides: Partial<EnrichmentResult>): EnrichmentResult {
  return {
    providerId: PROVIDER_ID, providerName: PROVIDER_NAME,
    status: 'ok', summary: '', severity: 'unknown', confidence: 'unknown',
    data: {}, rawAvailable: false, checkedAt: now(), fromCache: false,
    ...overrides,
  };
}

interface RipeAsn { asn?: number; holder?: string }
interface RipePrefixData { announced?: boolean; asns?: RipeAsn[]; block?: { name?: string; desc?: string; country?: string } }
interface RipeAsnData { asn?: number; holder?: string; block?: { name?: string; desc?: string; country?: string } }
interface RipeResponse<T> { status?: string; status_code?: number; data?: T }

async function ripeGet<T>(path: string, signal: AbortSignal): Promise<T> {
  const res = await fetch(`${BASE}/${path}`, { headers: { Accept: 'application/json' }, signal });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const json = (await res.json()) as RipeResponse<T>;
  return json.data as T;
}

export async function bgpview(ioc: IocInput, _options: EnrichOptions): Promise<EnrichmentResult> {
  const supported = ['ipv4', 'ipv6', 'asn', 'cidr'];
  if (!supported.includes(ioc.type)) {
    return makeResult({ status: 'unsupported_ioc', summary: `RIPE Stat does not support IOC type: ${ioc.type}.` });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    if (ioc.type === 'ipv4' || ioc.type === 'ipv6') {
      const d = await ripeGet<RipePrefixData>(
        `prefix-overview/data.json?resource=${encodeURIComponent(ioc.normalised)}`,
        controller.signal,
      );
      clearTimeout(timeout);

      const asns = d?.asns ?? [];
      const primary = asns[0];
      const summaryParts: string[] = [];
      if (primary?.asn) summaryParts.push(`ASN: ${primary.asn} (${primary.holder ?? 'unknown'})`);
      if (d?.block?.country) summaryParts.push(`Country: ${d.block.country}`);
      if (!d?.announced) summaryParts.push('Not announced');

      return makeResult({
        status: 'ok',
        summary: `RIPE Stat: ${summaryParts.join(' | ') || 'No routing data found.'}`,
        severity: 'unknown', confidence: primary?.asn ? 'high' : 'low',
        data: { asn: primary?.asn, asnHolder: primary?.holder, announced: d?.announced, country: d?.block?.country },
        rawAvailable: true,
        sourceUrl: `https://stat.ripe.net/${ioc.normalised}`,
        sourceReliability: 'passive-infra' as const,
        keyFacts: [
          ...(primary?.asn ? [{ label: 'ASN', value: `AS${primary.asn}` }] : []),
          ...(primary?.holder ? [{ label: 'ASN Holder', value: primary.holder }] : []),
          ...(d?.block?.country ? [{ label: 'Country', value: d.block.country }] : []),
          { label: 'Announced', value: d?.announced ? 'Yes' : 'No' },
        ],
      });
    }

    if (ioc.type === 'asn') {
      const asnNum = ioc.normalised.replace(/^AS/i, '');
      const d = await ripeGet<RipeAsnData>(
        `as-overview/data.json?resource=AS${asnNum}`,
        controller.signal,
      );
      clearTimeout(timeout);

      return makeResult({
        status: 'ok',
        summary: `RIPE Stat: ASN ${d?.asn} — ${d?.holder ?? 'unknown'}, ${d?.block?.country ?? 'unknown'}.`,
        severity: 'unknown', confidence: d?.asn ? 'high' : 'low',
        data: { asn: d?.asn, holder: d?.holder, country: d?.block?.country },
        rawAvailable: true,
        sourceUrl: `https://stat.ripe.net/AS${asnNum}`,
        sourceReliability: 'passive-infra' as const,
        keyFacts: [
          ...(d?.asn ? [{ label: 'ASN', value: `AS${d.asn}` }] : []),
          ...(d?.holder ? [{ label: 'Holder', value: d.holder }] : []),
          ...(d?.block?.country ? [{ label: 'Country', value: d.block.country }] : []),
        ],
      });
    }

    // CIDR
    const d = await ripeGet<RipePrefixData>(
      `prefix-overview/data.json?resource=${encodeURIComponent(ioc.normalised)}`,
      controller.signal,
    );
    clearTimeout(timeout);
    const primary = d?.asns?.[0];

    return makeResult({
      status: 'ok',
      summary: `RIPE Stat: Prefix ${ioc.normalised} — ASN ${primary?.asn ?? 'unknown'} (${primary?.holder ?? 'unknown'}), ${d?.block?.country ?? 'unknown'}.`,
      severity: 'unknown', confidence: primary?.asn ? 'high' : 'low',
      data: { asn: primary?.asn, holder: primary?.holder, country: d?.block?.country, announced: d?.announced },
      rawAvailable: true,
      sourceUrl: `https://stat.ripe.net/${ioc.normalised}`,
      sourceReliability: 'passive-infra' as const,
      keyFacts: [
        ...(primary?.asn ? [{ label: 'ASN', value: `AS${primary.asn}` }] : []),
        ...(primary?.holder ? [{ label: 'Holder', value: primary.holder }] : []),
        ...(d?.block?.country ? [{ label: 'Country', value: d.block.country }] : []),
        { label: 'Announced', value: d?.announced ? 'Yes' : 'No' },
      ],
    });
  } catch (err) {
    clearTimeout(timeout);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({ status: 'error', summary: isTimeout ? 'RIPE Stat request timed out.' : 'RIPE Stat request failed.', errorMessage: err instanceof Error ? err.message : String(err) });
  }
}
