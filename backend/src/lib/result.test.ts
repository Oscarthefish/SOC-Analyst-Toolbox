import { describe, it, expect } from 'vitest';
import { resultFactory } from './result.js';

describe('resultFactory', () => {
  const make = resultFactory('vt', 'VirusTotal');

  it('fills every field with defaults and the provider identity', () => {
    const r = make({});
    expect(r).toMatchObject({
      providerId: 'vt', providerName: 'VirusTotal', status: 'ok', summary: '', severity: 'unknown',
      confidence: 'unknown', data: {}, rawAvailable: false, fromCache: false,
    });
    expect(Number.isNaN(Date.parse(r.checkedAt))).toBe(false);
  });

  it('lets adapters override any field', () => {
    expect(make({ status: 'missing_key', severity: 'high', providerName: 'VT' })).toMatchObject({ status: 'missing_key', severity: 'high', providerName: 'VT' });
  });

  it('returns a fresh data object each time', () => {
    const a = make({}); const b = make({});
    expect(a.data).not.toBe(b.data);
  });
});
