import { describe, it, expect } from 'vitest';
import { generateToolId, validateToolForm, formToTool, DEFAULT_TOOL_FORM, TOOL_ID_RE } from './customTools';

describe('generateToolId', () => {
  it('slugifies the name with a prefix', () => {
    expect(generateToolId('Splunk IP Search', new Set())).toBe('custom-splunk-ip-search');
  });

  it('de-duplicates against existing ids', () => {
    expect(generateToolId('Jira', new Set(['custom-jira', 'custom-jira-2']))).toBe('custom-jira-3');
  });

  it('always produces an id the backend accepts, even for long or non-Latin names', () => {
    const long = 'Internal SIEM correlation search for outbound connections from finance VLAN hosts';
    for (const name of [long, '攻撃サーフェス', '!!!', 'a'.repeat(200)]) {
      const taken = new Set<string>();
      for (let i = 0; i < 15; i++) {
        const id = generateToolId(name, taken);
        expect(id).toMatch(TOOL_ID_RE);
        taken.add(id);
      }
    }
  });
});

describe('validateToolForm', () => {
  it('requires a name, an http(s) URL template and at least one IOC type', () => {
    expect(Object.keys(validateToolForm(DEFAULT_TOOL_FORM)).sort()).toEqual(['inputTypes', 'name', 'urlTemplate']);
    expect(validateToolForm({ ...DEFAULT_TOOL_FORM, name: 'x', urlTemplate: 'javascript:alert(1)', inputTypes: ['ipv4'] }))
      .toEqual({ urlTemplate: 'Must start with https:// or http://' });
    expect(validateToolForm({ ...DEFAULT_TOOL_FORM, name: 'x', urlTemplate: 'https://x.test/{{ip}}', inputTypes: ['ipv4'] })).toEqual({});
  });
});

describe('formToTool', () => {
  it('trims fields, splits tags and defaults the risk note', () => {
    const tool = formToTool({ ...DEFAULT_TOOL_FORM, name: ' Splunk ', urlTemplate: ' https://s.test/{{ip}} ', inputTypes: ['ipv4'], tags: 'siem, internal ,' }, new Set());
    expect(tool).toMatchObject({ id: 'custom-splunk', name: 'Splunk', urlTemplate: 'https://s.test/{{ip}}', tags: ['siem', 'internal'], riskNote: 'This is a custom tool.' });
  });
});
