import { describe, it, expect } from 'vitest';
import { detectIoc, normalizeIocInput } from './detectIoc';

describe('normalizeIocInput', () => {
  it('refangs brackets, parentheses and hxxp schemes', () => {
    expect(normalizeIocInput('hxxps://evil[.]example(.)com/x')).toBe('https://evil.example.com/x');
    expect(normalizeIocInput('HXXP://a[.]b')).toBe('http://a.b');
  });

  it('strips zero-width characters and surrounding whitespace', () => {
    expect(normalizeIocInput('  8.8​.8.8﻿ ')).toBe('8.8.8.8');
  });
});

describe('detectIoc', () => {
  it('returns unknown for empty input', () => {
    expect(detectIoc('   ')).toMatchObject({ type: 'unknown', normalised: '' });
  });

  describe('IPv4 and CIDR', () => {
    it('detects a valid IPv4 address', () => {
      expect(detectIoc('185.220.101.4')).toMatchObject({ type: 'ipv4', confidence: 'high', normalised: '185.220.101.4' });
    });

    it('rejects out-of-range octets', () => {
      expect(detectIoc('999.1.1.1').type).toBe('unknown');
    });

    it('detects a valid CIDR', () => {
      expect(detectIoc('10.0.0.0/8')).toMatchObject({ type: 'cidr', normalised: '10.0.0.0/8' });
    });

    it('rejects CIDRs with invalid octets or prefix', () => {
      expect(detectIoc('10.0.0.0/40').type).toBe('unknown');
      expect(detectIoc('300.0.0.0/8').type).toBe('unknown');
    });
  });

  describe('IPv6', () => {
    it('detects full and compressed forms, lowercased', () => {
      expect(detectIoc('2001:0DB8:85A3:0000:0000:8A2E:0370:7334')).toMatchObject({ type: 'ipv6', normalised: '2001:0db8:85a3:0000:0000:8a2e:0370:7334' });
      expect(detectIoc('2001:db8::1').type).toBe('ipv6');
      expect(detectIoc('::1').type).toBe('ipv6');
    });

    it('does not treat clock times as IPv6', () => {
      expect(detectIoc('12:30:45').type).not.toBe('ipv6');
      expect(detectIoc('1:2:3').type).not.toBe('ipv6');
    });
  });

  describe('domains', () => {
    it('detects and lowercases a domain', () => {
      expect(detectIoc('Login.Example.COM')).toMatchObject({ type: 'domain', normalised: 'login.example.com', confidence: 'high' });
    });

    it('accepts a domain with a trailing path at medium confidence', () => {
      expect(detectIoc('evil.example.com/login')).toMatchObject({ type: 'domain', normalised: 'evil.example.com', confidence: 'medium' });
    });

    it('refangs a defanged domain', () => {
      expect(detectIoc('evil[.]example[.]com')).toMatchObject({ type: 'domain', normalised: 'evil.example.com' });
    });
  });

  describe('URLs', () => {
    it('detects a URL and extracts its parts', () => {
      const r = detectIoc('https://www.example.com/a/b?x=1&y=2');
      expect(r.type).toBe('url');
      expect(r.urlExtract).toMatchObject({
        scheme: 'https',
        hostname: 'www.example.com',
        domain: 'example.com',
        path: '/a/b',
        queryParamNames: ['x', 'y'],
      });
    });

    it('refangs a defanged URL', () => {
      expect(detectIoc('hxxps://evil[.]com/x').normalised).toBe('https://evil.com/x');
    });

    it('flags URLs carrying tokens or identifiers as sensitive', () => {
      expect(detectIoc('https://example.com/reset?token=abc').isSensitiveUrl).toBe(true);
      expect(detectIoc('https://example.com/login?session_id=1').isSensitiveUrl).toBe(true);
      expect(detectIoc('https://example.com/auth/callback?code=xyz').isSensitiveUrl).toBe(true);
    });

    it('does not flag ordinary paths that merely contain a sensitive substring', () => {
      expect(detectIoc('https://example.com/android/video-guide').isSensitiveUrl).toBe(false);
      expect(detectIoc('https://example.com/keyboards?colour=red').isSensitiveUrl).toBe(false);
    });
  });

  describe('hashes', () => {
    it.each([
      ['d41d8cd98f00b204e9800998ecf8427e', 'md5'],
      ['DA39A3EE5E6B4B0D3255BFEF95601890AFD80709', 'sha1'],
      ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'sha256'],
    ])('detects %s as %s and lowercases it', (hash, type) => {
      expect(detectIoc(hash)).toMatchObject({ type, normalised: hash.toLowerCase() });
    });
  });

  it('detects and lowercases email addresses', () => {
    expect(detectIoc('Alice@Example.com')).toMatchObject({ type: 'email', normalised: 'alice@example.com' });
  });

  it('detects and uppercases ASNs and CVEs', () => {
    expect(detectIoc('as15169')).toMatchObject({ type: 'asn', normalised: 'AS15169' });
    expect(detectIoc('cve-2024-3400')).toMatchObject({ type: 'cve', normalised: 'CVE-2024-3400' });
  });

  it('detects credentials as secrets', () => {
    const r = detectIoc('ghp_' + 'a'.repeat(36));
    expect(r).toMatchObject({ type: 'secret', isCredential: true, credentialType: 'GitHub PAT (classic)' });
  });

  it('detects raw email headers', () => {
    const headers = 'Received: from mail.example.com\nFrom: a@example.com\nSubject: hi';
    expect(detectIoc(headers)).toMatchObject({ type: 'unknown', isEmailHeader: true });
  });
});
