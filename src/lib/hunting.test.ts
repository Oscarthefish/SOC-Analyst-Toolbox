import { describe, it, expect } from 'vitest';
import { HUNT_TEMPLATES } from '../data/huntQueries';
import type { Platform } from '../data/huntQueries';
import { TECHNIQUE_BY_ID } from '../data/attack';
import { groupIndicators, renderQuery, buildHunts, techniqueMatches, DEFAULT_HUNT_SETTINGS } from './hunting';
import type { HuntSettings } from './hunting';

const settings = (platform: Platform, over: Partial<HuntSettings> = {}): HuntSettings => ({ ...DEFAULT_HUNT_SETTINGS, platform, ...over });

const SAMPLE = groupIndicators([
  { type: 'ipv4', normalised: '185.220.101.4' },
  { type: 'domain', normalised: 'evil.example' },
  { type: 'url', normalised: 'https://login.evil.example/reset?t=1' },
  { type: 'sha256', normalised: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
  { type: 'md5', normalised: '44d88612fea8a8f36de82e1278abb02f' },
  { type: 'email', normalised: 'payroll@acme-hr.co' },
]);

describe('hunt templates', () => {
  it('reference only catalogued techniques and render with no placeholders left', () => {
    for (const t of HUNT_TEMPLATES) {
      for (const id of t.techniques) expect(TECHNIQUE_BY_ID.has(id), `${t.id} → ${id}`).toBe(true);
      for (const p of t.platforms) {
        const group = t.ioc ? SAMPLE.find(g => g.kind === t.ioc && (!t.hashTypes || t.hashTypes.includes(g.hashType!))) : undefined;
        if (t.ioc) expect(group, t.id).toBeDefined();
        const out = renderQuery(t, settings(p), group);
        expect(out, `${t.id} (${p})`).not.toMatch(/\{\{/);
      }
    }
  });

  it('have unique ids', () => {
    const ids = HUNT_TEMPLATES.map(t => t.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('use the platform’s time column', () => {
    for (const t of HUNT_TEMPLATES.filter(x => x.platforms.includes('defender') && !x.ioc)) {
      expect(renderQuery(t, settings('defender'))).not.toContain('TimeGenerated');
    }
  });
});

describe('renderQuery', () => {
  const ipSweep = HUNT_TEMPLATES.find(t => t.id === 'kql-ip-device-network')!;
  const splIp = HUNT_TEMPLATES.find(t => t.id === 'spl-ip-network')!;

  it('renders KQL lists, time column and lookback', () => {
    const out = renderQuery(ipSweep, settings('defender', { lookback: '30d' }), { kind: 'ip', values: ['1.2.3.4', '5.6.7.8'] });
    expect(out).toContain('let iocs = dynamic(["1.2.3.4", "5.6.7.8"]);');
    expect(out).toContain('| where Timestamp > ago(30d)');
  });

  it('renders SPL lists, earliest and the configured base search', () => {
    const s = settings('splunk', { lookback: '24h' });
    s.splunk = { ...s.splunk, network: 'index=pan sourcetype=pan:traffic' };
    const out = renderQuery(splIp, s, { kind: 'ip', values: ['1.2.3.4'] });
    expect(out.startsWith('index=pan sourcetype=pan:traffic earliest=-24h (src_ip IN ("1.2.3.4")')).toBe(true);
  });

  it('escapes quotes and backslashes', () => {
    const out = renderQuery(ipSweep, settings('sentinel'), { kind: 'ip', values: ['a"b\\c'] });
    expect(out).toContain('dynamic(["a\\"b\\\\c"])');
  });

  it('uses the right hash column and derives hosts from URLs', () => {
    const hashT = HUNT_TEMPLATES.find(t => t.id === 'kql-hash-process')!;
    expect(renderQuery(hashT, settings('sentinel'), { kind: 'hash', hashType: 'md5', values: ['x'] })).toContain('InitiatingProcessMD5 in~ (iocs)');
    const urlT = HUNT_TEMPLATES.find(t => t.id === 'kql-url-device-network')!;
    expect(renderQuery(urlT, settings('sentinel'), { kind: 'url', values: ['https://a.example/x', 'https://a.example/y'] })).toContain('dynamic(["a.example"])');
  });
});

describe('groupIndicators / buildHunts', () => {
  it('groups by kind, splits hash types and drops unsupported types', () => {
    const groups = groupIndicators([
      { type: 'ipv4', normalised: '1.1.1.1' }, { type: 'ipv6', normalised: '::1' }, { type: 'ipv4', normalised: '1.1.1.1' },
      { type: 'md5', normalised: 'a' }, { type: 'sha256', normalised: 'b' }, { type: 'cve', normalised: 'CVE-2024-1' },
    ]);
    expect(groups).toEqual([
      { kind: 'ip', values: ['1.1.1.1', '::1'] },
      { kind: 'hash', hashType: 'md5', values: ['a'] },
      { kind: 'hash', hashType: 'sha256', values: ['b'] },
    ]);
  });

  it('skips email attachment sweeps for MD5 (the table only has SHA256)', () => {
    const { sweeps } = buildHunts([{ kind: 'hash', hashType: 'md5', values: ['a'] }], [], settings('defender'));
    expect(sweeps.map(s => s.template.id)).not.toContain('kql-hash-email');
  });

  it('selects technique hunts for the platform, matching parents and sub-techniques', () => {
    expect(techniqueMatches('T1110', 'T1110.003')).toBe(true);
    expect(techniqueMatches('T1110', 'T1021')).toBe(false);
    const { hunts } = buildHunts([], ['T1110'], settings('sentinel'));
    expect(hunts.map(h => h.template.id)).toEqual(expect.arrayContaining(['kql-t1110-signin', 'kql-t1110-spray']));
    expect(hunts.every(h => h.template.platforms.includes('sentinel'))).toBe(true);
    expect(buildHunts([], ['T1110'], settings('splunk')).hunts.every(h => h.template.id.startsWith('spl-'))).toBe(true);
  });
});
