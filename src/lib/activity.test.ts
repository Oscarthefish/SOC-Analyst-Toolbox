import { describe, it, expect } from 'vitest';
import { lastSevenDays, dailyCounts, topCounts } from './activity';

const at = (iso: string, severity: 'high' | 'benign' | 'unknown') => ({ savedAt: iso, result: { overall: { severity } } });

describe('lastSevenDays', () => {
  it('buckets items into the seven local days ending today and ignores older ones', () => {
    const now = new Date(2026, 9, 20, 15, 0);
    const cols = lastSevenDays([
      at(new Date(2026, 9, 20, 9).toISOString(), 'high'),
      at(new Date(2026, 9, 20, 1).toISOString(), 'unknown'),
      at(new Date(2026, 9, 14, 23).toISOString(), 'benign'),
      at(new Date(2026, 9, 13, 23).toISOString(), 'high'),
    ], now);
    expect(cols).toHaveLength(7);
    expect(cols[6]).toMatchObject({ label: 'Today', mix: expect.objectContaining({ high: 1, info: 1 }) });
    expect(cols[0]!.mix.benign).toBe(1);
    expect(cols.reduce((n, c) => n + c.mix.high, 0)).toBe(1);
  });
});

describe('dailyCounts', () => {
  it('counts items per category per day and drops items outside the window', () => {
    const now = new Date(2026, 9, 20, 12);
    const items = [
      { d: new Date(2026, 9, 20, 8).toISOString(), t: 'cve' },
      { d: new Date(2026, 9, 20, 9).toISOString(), t: 'ransomware' },
      { d: new Date(2026, 9, 18, 9).toISOString(), t: 'cve' },
      { d: new Date(2026, 9, 1).toISOString(), t: 'cve' },
      { d: 'not a date', t: 'cve' },
    ];
    const cols = dailyCounts(items, i => i.d, i => i.t, 3, now);
    expect(cols.map(c => c.values)).toEqual([{ cve: 1 }, {}, { cve: 1, ransomware: 1 }]);
  });
});

describe('topCounts', () => {
  it('ranks values and skips blanks and placeholders', () => {
    expect(topCounts(['US', 'BR', 'US', '', null, 'Not Found', ' US '], ['not found']))
      .toEqual([{ label: 'US', value: 3 }, { label: 'BR', value: 1 }]);
  });
});
