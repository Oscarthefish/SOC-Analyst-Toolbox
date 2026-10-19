import { describe, it, expect } from 'vitest';
import type { EnrichmentResult } from '../types/enrichment';
import { buildRelationships } from './relationships';
import { severityMix, flaggedCount, countSeverities } from './severityMix';

function result(providerName: string, over: Partial<EnrichmentResult> = {}): EnrichmentResult {
  return {
    providerId: providerName.toLowerCase(), providerName, status: 'ok', summary: '', severity: 'unknown',
    confidence: 'high', data: {}, rawAvailable: false, checkedAt: '2026-10-20T00:00:00Z', fromCache: false, ...over,
  };
}

describe('buildRelationships', () => {
  it('merges the same ASN and country across providers and records each source', () => {
    const nodes = buildRelationships([
      result('Shodan', { keyFacts: [{ label: 'ASN', value: 'AS60729' }, { label: 'Country', value: 'DE' }] }),
      result('IPinfo', { keyFacts: [{ label: 'ASN', value: 'AS60729 Zwiebelfreunde e.V.' }, { label: 'Country', value: 'Germany' }] }),
    ], '185.220.101.4');
    const asn = nodes.find(n => n.role === 'ASN');
    expect(asn).toMatchObject({ value: 'AS60729', sources: ['Shodan', 'IPinfo'], pivot: 'AS60729' });
    expect(nodes.filter(n => n.role === 'Country')).toEqual([expect.objectContaining({ value: 'Germany', sources: ['Shodan', 'IPinfo'] })]);
  });

  it('turns resolved IPs, certificate names and nameservers into pivotable hosts', () => {
    const nodes = buildRelationships([
      result('DNS', { resolvedIps: ['93.184.216.34'], keyFacts: [{ label: 'Nameservers', value: 'A.IANA-SERVERS.NET, b.iana-servers.net' }] }),
      result('crt.sh', { relatedDomains: ['*.example.com', 'example.com'] }),
    ], 'example.com');
    expect(nodes.filter(n => n.kind === 'host').map(n => n.pivot).sort())
      .toEqual(['93.184.216.34', 'a.iana-servers.net', 'b.iana-servers.net', 'example.com']);
  });

  it('ignores providers without data, empty values and the indicator itself', () => {
    const nodes = buildRelationships([
      result('Censys', { status: 'error', keyFacts: [{ label: 'ASN', value: 'AS1' }] }),
      result('Shodan', { keyFacts: [{ label: 'Open ports', value: 'none' }, { label: 'Org', value: '' }] }),
    ], '1.2.3.4');
    expect(nodes).toEqual([]);
  });

  it('splits threat labels and strips the count from open ports', () => {
    const nodes = buildRelationships([
      result('ThreatFox', { keyFacts: [{ label: 'Tags', value: 'cobaltstrike, c2' }] }),
      result('Shodan', { keyFacts: [{ label: 'Open ports', value: '2 (22, 9001)' }] }),
    ], '1.2.3.4');
    expect(nodes.filter(n => n.kind === 'threat').map(n => n.value)).toEqual(['c2', 'cobaltstrike']);
    expect(nodes.find(n => n.kind === 'exposure')?.value).toBe('22, 9001');
  });
});

describe('severityMix', () => {
  it('buckets results and counts flagged providers', () => {
    const results = [
      result('A', { severity: 'high' }), result('B', { severity: 'medium' }), result('C', { severity: 'unknown' }),
      result('D', { severity: 'benign' }), result('E', { status: 'missing_key' }),
    ];
    expect(severityMix(results)).toMatchObject({ high: 1, medium: 1, info: 1, benign: 1, none: 1, critical: 0 });
    expect(flaggedCount(results)).toBe(2);
    expect(countSeverities(['high', 'high', 'unknown'])).toMatchObject({ high: 2, info: 1 });
  });
});
