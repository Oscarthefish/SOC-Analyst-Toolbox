import { describe, it, expect } from 'vitest';
import type { EnrichmentResult } from '../types/enrichment';
import { deriveTechniques, WORKFLOW_TECHNIQUES } from './attackMapping';
import { TECHNIQUE_BY_ID, TACTIC_BY_ID, TECHNIQUES, attackUrl } from '../data/attack';

function result(providerName: string, over: Partial<EnrichmentResult> = {}): EnrichmentResult {
  return {
    providerId: providerName.toLowerCase(), providerName, status: 'ok', summary: '', severity: 'unknown',
    confidence: 'high', data: {}, rawAvailable: false, checkedAt: '2026-10-20T00:00:00Z', fromCache: false, ...over,
  };
}

describe('deriveTechniques', () => {
  it('ranks reported techniques before inferred and context ones', () => {
    const hits = deriveTechniques([
      result('GreyNoise', { keyFacts: [{ label: 'Tags', value: 'SSH Bruteforcer, Tor' }] }),
      result('AlienVault OTX', { attackTechniques: [{ id: 'T1071.001', name: 'Web Protocols' }, { id: 'T9999', name: 'Something new' }] }),
    ], { id: 'suspicious-connection', name: 'Suspicious Connection' });

    expect(hits[0]).toMatchObject({ id: 'T1071.001', evidence: [{ kind: 'reported', source: 'AlienVault OTX' }] });
    expect(hits.find(h => h.id === 'T9999')).toMatchObject({ name: 'Something new', tactic: '' });
    expect(hits.find(h => h.id === 'T1110')?.evidence).toEqual([{ kind: 'inferred', source: 'GreyNoise', detail: 'SSH Bruteforcer' }]);
    expect(hits.find(h => h.id === 'T1021.004')).toBeDefined();
    expect(hits.find(h => h.id === 'T1090.003')?.evidence[0]).toMatchObject({ detail: 'Tor' });
    expect(hits.find(h => h.id === 'T1571')?.evidence).toEqual([{ kind: 'context', source: 'Suspicious Connection' }]);
  });

  it('ignores providers without data and labels with no rule', () => {
    expect(deriveTechniques([
      result('ThreatFox', { status: 'error', keyFacts: [{ label: 'Threat types', value: 'botnet_cc' }] }),
      result('OTX', { keyFacts: [{ label: 'Tags', value: 'finance, invoice' }] }),
    ])).toEqual([]);
  });

  it('maps ThreatFox and Safe Browsing threat types', () => {
    const ids = deriveTechniques([
      result('ThreatFox', { keyFacts: [{ label: 'Threat types', value: 'botnet_cc, payload_delivery' }] }),
      result('Safe Browsing', { keyFacts: [{ label: 'Threat types', value: 'SOCIAL_ENGINEERING' }] }),
    ]).map(h => h.id).sort();
    expect(ids).toEqual(['T1071', 'T1105', 'T1566.002']);
  });
});

describe('ATT&CK catalogue', () => {
  it('only references known techniques and tactics', () => {
    for (const ids of Object.values(WORKFLOW_TECHNIQUES)) for (const id of ids) expect(TECHNIQUE_BY_ID.has(id), id).toBe(true);
    for (const tech of TECHNIQUES) for (const ta of tech.tactics) expect(TACTIC_BY_ID.has(ta), `${tech.id} ${ta}`).toBe(true);
  });

  it('builds attack.mitre.org links for sub-techniques', () => {
    expect(attackUrl('T1071.001')).toBe('https://attack.mitre.org/techniques/T1071/001/');
  });
});
