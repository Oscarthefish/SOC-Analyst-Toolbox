import { promises as dnsPromises } from 'dns';
import type { IocInput, EnrichmentResult, EnrichOptions } from '../types.js';

const PROVIDER_ID = 'dns';
const PROVIDER_NAME = 'DNS Resolution';

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

export async function dns(
  ioc: IocInput,
  _options: EnrichOptions,
): Promise<EnrichmentResult> {
  if (ioc.type !== 'domain') {
    return makeResult({
      status: 'unsupported_ioc',
      summary: `DNS resolution does not support IOC type: ${ioc.type} (supports: domain).`,
    });
  }

  const hostname = ioc.normalised;

  const [v4Result, v6Result] = await Promise.allSettled([
    dnsPromises.resolve4(hostname),
    dnsPromises.resolve6(hostname),
  ]);

  const ipv4s: string[] = v4Result.status === 'fulfilled' ? v4Result.value : [];
  const ipv6s: string[] = v6Result.status === 'fulfilled' ? v6Result.value : [];
  const allIps = [...ipv4s, ...ipv6s];

  if (allIps.length === 0) {
    const reason = v4Result.status === 'rejected'
      ? (v4Result.reason as NodeJS.ErrnoException).code ?? 'NXDOMAIN'
      : 'no records';
    return makeResult({
      status: 'ok',
      summary: `DNS: No records found for ${hostname} (${reason}).`,
      severity: 'unknown',
      confidence: 'low',
      data: { ipv4s: [], ipv6s: [] },
      resolvedIps: [],
      sourceReliability: 'passive-infra',
      keyFacts: [{ label: 'Resolves', value: `No — ${reason}` }],
    });
  }

  const ipv6Preview = ipv6s.length > 2
    ? `${ipv6s.slice(0, 2).join(', ')} +${ipv6s.length - 2} more`
    : ipv6s.join(', ');

  return makeResult({
    status: 'ok',
    summary: `DNS: ${hostname} resolves to ${ipv4s.join(', ')}${ipv6s.length > 0 ? ` (+ ${ipv6s.length} IPv6)` : ''}.`,
    severity: 'unknown',
    confidence: 'high',
    data: { ipv4s, ipv6s },
    resolvedIps: ipv4s,
    sourceReliability: 'passive-infra',
    keyFacts: [
      ...(ipv4s.length > 0 ? [{ label: 'IPv4', value: ipv4s.join(', ') }] : []),
      ...(ipv6s.length > 0 ? [{ label: 'IPv6', value: ipv6Preview }] : []),
    ],
  });
}
