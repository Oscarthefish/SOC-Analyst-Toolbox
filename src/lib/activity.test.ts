import { describe, it, expect } from 'vitest';
import { lastSevenDays } from './activity';

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
