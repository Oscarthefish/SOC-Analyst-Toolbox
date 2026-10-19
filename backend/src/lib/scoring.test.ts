import { describe, it, expect } from 'vitest';
import type { EnrichmentResult } from '../types.js';
import { computeOverallAssessment, detectContradictions, detectVpnOrTor, EMAIL_ACTIONS } from './scoring.js';

function r(providerId: string, overrides: Partial<EnrichmentResult> = {}): EnrichmentResult {
  return {
    providerId,
    providerName: providerId,
    status: 'ok',
    summary: '',
    severity: 'unknown',
    confidence: 'medium',
    data: {},
    rawAvailable: false,
    checkedAt: '2026-01-01T00:00:00Z',
    fromCache: false,
    freshnessLabel: 'last7d',
    ...overrides,
  };
}

describe('computeOverallAssessment', () => {
  it('is critical when any active source is critical', () => {
    const a = computeOverallAssessment([r('virustotal', { severity: 'critical' }), r('greynoise', { severity: 'benign' })]);
    expect(a.severity).toBe('critical');
    expect(a.recommendedActions[0]).toMatch(/isolate/i);
  });

  it('is high with one high and one medium source', () => {
    expect(computeOverallAssessment([r('virustotal', { severity: 'high' }), r('otx', { severity: 'medium' })]).severity).toBe('high');
  });

  it('is benign only when every active source is benign', () => {
    expect(computeOverallAssessment([r('virustotal', { severity: 'benign' }), r('greynoise', { severity: 'benign' })]).severity).toBe('benign');
    expect(computeOverallAssessment([r('virustotal', { severity: 'benign' }), r('greynoise', { severity: 'unknown' })]).severity).toBe('unknown');
  });

  it('ignores passive context providers when scoring severity', () => {
    const a = computeOverallAssessment([r('whois', { severity: 'high' }), r('ipinfo', { severity: 'critical' })]);
    expect(a.severity).toBe('unknown');
  });

  it('ignores failed and missing-key results', () => {
    const a = computeOverallAssessment([
      r('virustotal', { status: 'error', severity: 'critical' }),
      r('shodan', { status: 'missing_key', severity: 'high' }),
    ]);
    expect(a.severity).toBe('unknown');
    expect(a.summary).toMatch(/No enrichment providers returned data/);
  });

  it('counts cached results as data', () => {
    expect(computeOverallAssessment([r('virustotal', { status: 'cached', severity: 'medium' })]).severity).toBe('medium');
  });

  it('rates confidence by number and freshness of active sources', () => {
    const fresh = ['virustotal', 'greynoise', 'abuseipdb'].map(id => r(id, { severity: 'low' }));
    expect(computeOverallAssessment(fresh).confidence).toBe('high');
    expect(computeOverallAssessment(fresh.slice(0, 1)).confidence).toBe('medium');
    const stale = fresh.map(x => ({ ...x, freshnessLabel: 'historical' as const }));
    expect(computeOverallAssessment(stale).confidence).toBe('low');
    expect(computeOverallAssessment([]).confidence).toBe('low');
  });

  it('raises Tor nodes to at least medium and VPNs to at least low', () => {
    const benign = [r('virustotal', { severity: 'benign' })];
    expect(computeOverallAssessment(benign, { isTor: true, isVpn: false, signals: [] }).severity).toBe('medium');
    expect(computeOverallAssessment(benign, { isTor: false, isVpn: true, signals: [] }).severity).toBe('low');
    expect(computeOverallAssessment([r('virustotal', { severity: 'high' })], { isTor: true, isVpn: false, signals: [] }).severity).toBe('high');
  });

  it('uses the supplied action wording without changing the verdict', () => {
    const results = [r('virustotal', { severity: 'high' })];
    const email = computeOverallAssessment(results, undefined, EMAIL_ACTIONS);
    expect(email.severity).toBe(computeOverallAssessment(results).severity);
    expect(email.recommendedActions.join(' ')).toMatch(/Quarantine the email/);
    const tor = computeOverallAssessment([r('virustotal', { severity: 'benign' })], { isTor: true, isVpn: false, signals: [] }, EMAIL_ACTIONS);
    expect(tor.recommendedActions[0]).toBe(EMAIL_ACTIONS.tor);
  });
});

describe('detectContradictions', () => {
  it('flags benign vs malicious disagreement between active sources', () => {
    const flags = detectContradictions([r('virustotal', { severity: 'high' }), r('greynoise', { severity: 'benign' })]);
    expect(flags.map(f => f.type)).toContain('CONFLICT_BENIGN_VS_MALICIOUS');
  });

  it('does not flag disagreement involving passive sources', () => {
    expect(detectContradictions([r('whois', { severity: 'high' }), r('greynoise', { severity: 'benign' })])).toEqual([]);
  });

  it('flags uncorroborated low VirusTotal detection counts', () => {
    const vt = r('virustotal', { severity: 'medium', data: { malicious: 1, harmless: 60, undetected: 10, suspicious: 0 } });
    expect(detectContradictions([vt]).map(f => f.type)).toEqual(['LOW_DETECTION_NO_CORROBORATION']);
  });

  it('flags newly registered domains with no detections', () => {
    const flags = detectContradictions([r('whois', { data: { domainAge: 3 } }), r('virustotal', { severity: 'benign' })]);
    expect(flags.map(f => f.type)).toContain('NEWLY_REGISTERED_UNDETECTED');
  });

  it('flags old domains with no Wayback history', () => {
    const flags = detectContradictions([r('whois', { data: { domainAge: 2000 } }), r('wayback', { keyFacts: [] })]);
    expect(flags.map(f => f.type)).toContain('DOMAIN_AGE_ARCHIVE_MISMATCH');
  });
});

describe('detectVpnOrTor', () => {
  it('detects Tor exit nodes from the Tor Project adapter', () => {
    const f = detectVpnOrTor([r('torproject', { data: { isTorNode: true, isExitNode: true } })]);
    expect(f.isTor).toBe(true);
    expect(f.signals[0]).toMatch(/exit node/);
  });

  it('detects commercial VPNs from org or usage type', () => {
    expect(detectVpnOrTor([r('ipinfo', { data: { org: 'AS9009 M247 Ltd (Mullvad)' } })]).isVpn).toBe(true);
    expect(detectVpnOrTor([r('abuseipdb', { data: { usageType: 'VPN Service' } })]).isVpn).toBe(true);
  });

  it('ignores ordinary hosting providers', () => {
    expect(detectVpnOrTor([r('ipinfo', { data: { org: 'AS15169 Google LLC' } })])).toMatchObject({ isTor: false, isVpn: false });
  });
});
