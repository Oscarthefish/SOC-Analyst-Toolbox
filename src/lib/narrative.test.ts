import { describe, it, expect } from 'vitest';
import { parseNarrative, buildSourceMap, findSourceUrl } from './narrative';
import type { EnrichmentResult } from '../types/enrichment';

const NARRATIVE = `VERDICT: **Likely Malicious**

KEY FINDINGS:
- [VirusTotal] 12/90 engines flag the IP
• [AbuseIPDB] confidence score 100
1. Hosted on bulletproof ASN

RECOMMENDED ACTIONS:
- Block at the perimeter
- Hunt for connections in proxy logs

ANALYST NOTES:
Shared hosting; confirm the specific site before blocking.`;

describe('parseNarrative', () => {
  it('extracts verdict, findings, actions and notes', () => {
    expect(parseNarrative(NARRATIVE)).toEqual({
      verdict: 'Likely Malicious',
      findings: ['[VirusTotal] 12/90 engines flag the IP', '[AbuseIPDB] confidence score 100', 'Hosted on bulletproof ASN'],
      actions: ['Block at the perimeter', 'Hunt for connections in proxy logs'],
      notes: 'Shared hosting; confirm the specific site before blocking.',
    });
  });

  it('returns empty sections for unstructured text', () => {
    expect(parseNarrative('Just some prose.')).toEqual({ verdict: null, findings: [], actions: [], notes: null });
  });
});

describe('source links', () => {
  const results = [
    { providerId: 'virustotal', providerName: 'VirusTotal', sourceUrl: 'https://vt.test/x' },
    { providerId: 'ipinfo', providerName: 'IPinfo' },
  ] as EnrichmentResult[];

  it('links a finding to the provider it mentions', () => {
    const map = buildSourceMap(results);
    expect(findSourceUrl('[VirusTotal] 12/90 engines', map)).toBe('https://vt.test/x');
    expect(findSourceUrl('IPinfo says hosting', map)).toBeNull();
  });
});
