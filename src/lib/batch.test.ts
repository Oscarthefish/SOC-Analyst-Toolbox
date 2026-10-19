import { describe, it, expect } from 'vitest';
import { parseBatchInput, rowsToCsv, topFinding, BATCH_LIMIT } from './batch';
import type { EnrichmentResult } from '../types/enrichment';

describe('parseBatchInput', () => {
  it('splits on newlines and commas, refangs, dedupes and skips unknowns', () => {
    const { rows } = parseBatchInput('8.8.8.8, evil[.]com\n8.8.8.8\nnot an ioc\n\nCVE-2024-3400');
    expect(rows.map(r => [r.normalised, r.type, r.status])).toEqual([
      ['8.8.8.8', 'ipv4', 'pending'],
      ['evil.com', 'domain', 'pending'],
      ['not an ioc', 'unknown', 'skipped'],
      ['CVE-2024-3400', 'cve', 'pending'],
    ]);
  });

  it('caps the batch and reports how many were left out', () => {
    const input = Array.from({ length: BATCH_LIMIT + 5 }, (_, i) => `10.0.0.${i}`).join('\n');
    const { rows, truncated } = parseBatchInput(input);
    expect(rows).toHaveLength(BATCH_LIMIT);
    expect(truncated).toBe(5);
  });
});

describe('rowsToCsv', () => {
  it('writes a header and quotes cells that need it', () => {
    const csv = rowsToCsv([{
      id: 'a', raw: 'a', normalised: 'evil.com', type: 'domain', status: 'done', severity: 'high', confidence: 'medium',
      sources: { withData: 3, total: 9 }, topFinding: 'Flagged by "X", phishing',
    }]);
    expect(csv).toBe(
      'indicator,type,status,severity,confidence,sources_with_data,sources_queried,top_finding\n' +
      'evil.com,domain,done,high,medium,3,9,"Flagged by ""X"", phishing"\n',
    );
  });

  it('neutralises spreadsheet formulas', () => {
    const csv = rowsToCsv([{ id: 'a', raw: 'a', normalised: 'x', type: 'domain', status: 'error', errorMsg: '=HYPERLINK("http://evil")' }]);
    expect(csv).toContain(`"'=HYPERLINK(""http://evil"")"`);
  });
});

describe('topFinding', () => {
  it('uses the most severe provider, preferring its first key fact', () => {
    const results = [
      { providerName: 'IPinfo', status: 'ok', severity: 'unknown', summary: 'Hosting' },
      { providerName: 'AbuseIPDB', status: 'ok', severity: 'high', summary: 'Reported', keyFacts: [{ label: 'Score', value: '100' }] },
    ] as EnrichmentResult[];
    expect(topFinding(results)).toBe('[AbuseIPDB] Score: 100');
    expect(topFinding([])).toBe('No data returned.');
  });
});
