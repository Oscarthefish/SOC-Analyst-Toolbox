import { describe, it, expect } from 'vitest';
import { detectIoc } from './detectIoc';
import { threatWatchLink } from './threatWatch';

const BASE = 'https://tw.example.ts.net';

describe('threatWatchLink', () => {
  it('opens a CVE on its vulnerability page', () => {
    expect(threatWatchLink(BASE, detectIoc('cve-2024-3400'))).toBe(`${BASE}/vuln/CVE-2024-3400`);
  });

  it('searches reporting for domains, IPs and hashes', () => {
    expect(threatWatchLink(BASE, detectIoc('evil[.]example.com'))).toBe(`${BASE}/search?q=evil.example.com`);
    expect(threatWatchLink(BASE, detectIoc('185.220.101.4'))).toBe(`${BASE}/search?q=185.220.101.4`);
    const sha = 'a'.repeat(64);
    expect(threatWatchLink(BASE, detectIoc(sha))).toBe(`${BASE}/search?q=${sha}`);
  });

  it('searches a URL by its host name only, never its path or query', () => {
    const link = threatWatchLink(BASE, detectIoc('https://login.evil.example.com/reset?token=abc123'));
    expect(link).toBe(`${BASE}/search?q=login.evil.example.com`);
  });

  it('gives no link without a configured instance or for input that should not leave the toolbox', () => {
    expect(threatWatchLink('', detectIoc('CVE-2024-3400'))).toBeNull();
    expect(threatWatchLink(BASE, detectIoc('not an indicator at all'))).toBeNull();
  });
});
