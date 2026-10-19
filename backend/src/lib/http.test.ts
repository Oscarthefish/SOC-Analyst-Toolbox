import { describe, it, expect } from 'vitest';
import { withDefaultUserAgent, USER_AGENT } from './http.js';

describe('withDefaultUserAgent', () => {
  it('adds a User-Agent when none is set, keeping other headers', () => {
    const h = new Headers(withDefaultUserAgent({ headers: { Accept: 'application/json' } }).headers);
    expect(h.get('User-Agent')).toBe(USER_AGENT);
    expect(h.get('Accept')).toBe('application/json');
  });

  it('keeps an explicit User-Agent', () => {
    const h = new Headers(withDefaultUserAgent({ headers: { 'user-agent': 'custom' } }).headers);
    expect(h.get('User-Agent')).toBe('custom');
  });

  it('preserves other request options', () => {
    const signal = new AbortController().signal;
    expect(withDefaultUserAgent({ method: 'POST', signal })).toMatchObject({ method: 'POST', signal });
  });
});
