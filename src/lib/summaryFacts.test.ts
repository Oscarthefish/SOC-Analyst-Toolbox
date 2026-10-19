import { describe, it, expect } from 'vitest';
import { extractSummaryFacts } from './summaryFacts';
import { buildComparison } from './providerComparison';
import type { EnrichmentResult } from '../types/enrichment';

function r(providerId: string, providerName: string, over: Partial<EnrichmentResult> = {}): EnrichmentResult {
  return {
    providerId, providerName, status: 'ok', summary: '', severity: 'unknown', confidence: 'medium',
    data: {}, rawAvailable: false, checkedAt: '', fromCache: false, ...over,
  };
}
const kf = (label: string, value: string) => ({ label, value });

describe('extractSummaryFacts', () => {
  it('collects headline facts from the providers that have them', () => {
    const facts = extractSummaryFacts([
      r('virustotal', 'VirusTotal', { severity: 'high', keyFacts: [kf('Detection ratio', '12/94')] }),
      r('abuseipdb', 'AbuseIPDB', { severity: 'high', keyFacts: [kf('Abuse score', '100')] }),
      r('cisakev', 'CISA KEV', { severity: 'critical' }),
    ]);
    expect(facts.map(f => `${f.label}=${f.value}`)).toEqual(['VT Detection=12/94', 'Abuse Score=100', 'CISA KEV=Actively exploited']);
  });

  it('ignores providers that failed or returned nothing', () => {
    expect(extractSummaryFacts([
      r('virustotal', 'VirusTotal', { status: 'error', keyFacts: [kf('Detection ratio', '1/1')] }),
      r('greynoise', 'GreyNoise', { keyFacts: [kf('Classification', 'unknown')] }),
    ])).toEqual([]);
  });

  it('reports the most recent last-seen date across providers', () => {
    const facts = extractSummaryFacts([
      r('otx', 'OTX', { lastSeenDate: '2026-01-02T00:00:00Z' }),
      r('threatfox', 'ThreatFox', { lastSeenDate: '2026-03-04T10:00:00Z' }),
    ]);
    expect(facts).toContainEqual({ label: 'Last Seen', value: '2026-03-04', source: 'ThreatFox' });
  });
});

describe('buildComparison', () => {
  it('compares registration and geolocation sources for an IP', () => {
    const groups = buildComparison([
      r('whois', 'WHOIS', { keyFacts: [kf('Country (registration)', 'DE'), kf('Network', 'TOR-EXIT')] }),
      r('ipinfo', 'IPinfo', { keyFacts: [kf('Location', 'Berlin, DE'), kf('ASN', 'AS60729')] }),
    ], 'ipv4');
    const loc = groups.find(g => g.rows.some(row => row.provider === 'WHOIS'));
    expect(loc?.rows.map(row => `${row.provider}: ${row.value} (${row.note})`)).toEqual([
      'WHOIS: DE (reg) · TOR-EXIT (registration)',
      'ipinfo: Berlin, DE · AS60729 (geolocation)',
    ]);
  });

  it('returns no groups when no provider has data', () => {
    expect(buildComparison([r('whois', 'WHOIS', { status: 'error' })], 'ipv4')).toEqual([]);
  });
});
