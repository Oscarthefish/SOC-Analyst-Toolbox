import { describe, it, expect } from 'vitest';
import { extractIocs } from './extractIocs';

const values = (text: string, type?: string) =>
  extractIocs(text).filter(r => !type || r.type === type).map(r => r.normalised);

describe('extractIocs', () => {
  it('extracts mixed indicators from a log line', () => {
    const log = [
      '2024-05-01 12:30:45 DENY src=185.220.101.4 dst=10.0.0.5 host=evil-cdn.net',
      'url=https://evil-cdn.net/payload.exe sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      'reported by soc@example.com, see CVE-2024-3400, origin AS13335',
    ].join('\n');
    const types = Object.fromEntries(extractIocs(log).map(r => [r.normalised, r.type]));

    expect(types).toMatchObject({
      '185.220.101.4': 'ipv4',
      '10.0.0.5': 'ipv4',
      'https://evil-cdn.net/payload.exe': 'url',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855': 'sha256',
      'soc@example.com': 'email',
      'CVE-2024-3400': 'cve',
      'AS13335': 'asn',
    });
  });

  it('deduplicates repeated indicators', () => {
    expect(values('1.2.3.4 then 1.2.3.4 again', 'ipv4')).toEqual(['1.2.3.4']);
  });

  it('strips trailing punctuation from URLs', () => {
    expect(values('Visit https://example.com/path.', 'url')).toEqual(['https://example.com/path']);
  });

  it('refangs defanged URLs and domains', () => {
    expect(values('see hxxps://evil[.]com/x', 'url')).toEqual(['https://evil.com/x']);
    expect(values('beacon to evil[.]example[.]com', 'domain')).toEqual(['evil.example.com']);
  });

  it('does not double-count URL hosts or email domains as domains', () => {
    expect(values('https://evil.com/a and bob@corp.com', 'domain')).toEqual([]);
  });

  it('excludes version strings and file names from domains', () => {
    expect(values('upgraded to 2.3.1 and ran setup.exe, report.pdf, config.json', 'domain')).toEqual([]);
  });

  it('ignores invalid IPv4 octets and CIDR prefixes', () => {
    expect(values('999.1.1.1', 'ipv4')).toEqual([]);
    expect(values('10.0.0.0/40', 'cidr')).toEqual([]);
  });

  it('still reports an IP that appears both alone and as a CIDR network address', () => {
    expect(values('10.0.0.0/8 and later 10.0.0.0 alone', 'ipv4')).toEqual(['10.0.0.0']);
  });

  it('does not also report a CIDR network address as an IPv4 address', () => {
    const r = extractIocs('blocked range 10.0.0.0/8');
    expect(r.map(x => `${x.type}:${x.normalised}`)).toEqual(['cidr:10.0.0.0/8']);
  });

  it('does not treat timestamps as IPv6 addresses', () => {
    expect(values('2024-05-01 12:30:45 and 09:00:00', 'ipv6')).toEqual([]);
  });

  it('extracts real IPv6 addresses', () => {
    expect(values('src=2001:db8::1 dst=fe80::1ff:fe23:4567:890a', 'ipv6')).toEqual(['2001:db8::1', 'fe80::1ff:fe23:4567:890a']);
  });

  it('suggests workflows per type', () => {
    expect(extractIocs('8.8.8.8')[0]!.suggestedWorkflowIds).toContain('ip-triage');
  });
});
