import { describe, it, expect } from 'vitest';
import { processDefang, defangUrlSmart, refangUrl } from './defang';
import { applyTemplate, buildTemplateVars, safeHref } from './template';
import { detectIoc } from './detectIoc';

describe('processDefang', () => {
  it.each([
    ['1.2.3.4', 'ipv4', '1[.]2[.]3[.]4', '1.2.3.4'],
    ['1[.]2[.]3[.]4', 'ipv4', '1[.]2[.]3[.]4', '1.2.3.4'],
    ['10.0.0.0/8', 'cidr', '10[.]0[.]0[.]0/8', '10.0.0.0/8'],
    ['example.com', 'domain', 'example[.]com', 'example.com'],
    ['a@example.com', 'email', 'a[@]example[.]com', 'a@example.com'],
    ['https://example.com/a.b', 'url', 'hxxps://example[.]com/a.b', 'https://example.com/a.b'],
    ['hxxp://evil[.]com/x', 'url', 'hxxp://evil[.]com/x', 'http://evil.com/x'],
  ])('%s → %s', (input, type, defanged, refanged) => {
    expect(processDefang(input)).toMatchObject({ type, defanged, refanged });
  });

  it('passes unrecognised input through unchanged', () => {
    expect(processDefang('not an ioc')).toMatchObject({ type: 'other', defanged: 'not an ioc' });
  });
});

describe('URL defang round trip', () => {
  it('only defangs the host, leaving the path intact', () => {
    expect(defangUrlSmart('https://a.b.com/x.y?q=1.2')).toBe('hxxps://a[.]b[.]com/x.y?q=1.2');
  });

  it('refangs back to the original', () => {
    const url = 'https://a.b.com/path';
    expect(refangUrl(defangUrlSmart(url))).toBe(url);
  });
});

describe('templates', () => {
  it('fills IP and encoded query variables', () => {
    const vars = buildTemplateVars(detectIoc('8.8.8.8'));
    expect(applyTemplate('https://x.test/ip/{{ip}}?q={{encodedQuery}}', vars)).toBe('https://x.test/ip/8.8.8.8?q=8.8.8.8');
  });

  it('uses the hostname as the search value for URLs', () => {
    const vars = buildTemplateVars(detectIoc('https://www.evil.com/a?b=c'));
    expect(applyTemplate('{{domain}}|{{encodedQuery}}', vars)).toBe('evil.com|evil.com');
  });

  it('leaves variables that do not apply to the type empty', () => {
    const vars = buildTemplateVars(detectIoc('example.com'));
    expect(applyTemplate('https://x.test/{{hash}}', vars)).toBe('https://x.test/');
  });
});

describe('safeHref', () => {
  it('allows http(s) and rejects other schemes', () => {
    expect(safeHref('https://a.test')).toBe('https://a.test');
    expect(safeHref('HTTP://a.test')).toBe('HTTP://a.test');
    expect(safeHref('javascript:alert(1)')).toBeUndefined();
    expect(safeHref(' javascript:alert(1)')).toBeUndefined();
    expect(safeHref('data:text/html,x')).toBeUndefined();
  });
});
