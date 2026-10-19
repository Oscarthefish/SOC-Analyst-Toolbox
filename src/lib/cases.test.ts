import { describe, it, expect, beforeEach } from 'vitest';
import { saveCase, loadCases, setCaseStatus, deleteCase, caseToMarkdown, caseFilename, internalSearches, emptyDraft } from './cases';
import { detectIoc } from './detectIoc';
import type { Workflow } from '../types/workflow';

// Minimal in-memory localStorage for the node test environment
const store = new Map<string, string>();
globalThis.localStorage = {
  getItem: k => store.get(k) ?? null,
  setItem: (k, v) => { store.set(k, String(v)); },
  removeItem: k => { store.delete(k); },
  clear: () => store.clear(),
  key: i => [...store.keys()][i] ?? null,
  get length() { return store.size; },
} as Storage;

const ioc = { original: '185.220.101.4', normalised: '185.220.101.4', type: 'ipv4' as const };
const workflow: Workflow = {
  id: 'ip-triage', name: 'IP Triage', description: '', allowedInputTypes: ['ipv4'], toolIds: [],
  checklist: ['Check reputation', 'Check internal logs'],
  internalSearches: [{ label: 'Firewall', template: 'src_ip={{value}}' }],
  expectedOutcome: '',
};

describe('case store', () => {
  beforeEach(() => store.clear());

  it('creates a case, defaulting the title to the indicator', () => {
    const { saved, cases } = saveCase({ ioc, workflowId: 'ip-triage', analysis: null, draft: emptyDraft() }, new Date('2026-01-01T00:00:00Z'));
    expect(saved).toMatchObject({ title: '185.220.101.4', status: 'open', createdAt: '2026-01-01T00:00:00.000Z' });
    expect(cases).toHaveLength(1);
  });

  it('updates an existing case and keeps its creation time', () => {
    const { saved } = saveCase({ ioc, workflowId: null, analysis: null, draft: emptyDraft() }, new Date('2026-01-01T00:00:00Z'));
    const { saved: updated, cases } = saveCase(
      { id: saved.id, ioc, workflowId: null, analysis: null, draft: { ...emptyDraft(), verdict: 'malicious', notes: 'Tor exit' } },
      new Date('2026-01-02T00:00:00Z'),
    );
    expect(cases).toHaveLength(1);
    expect(updated).toMatchObject({ id: saved.id, verdict: 'malicious', createdAt: saved.createdAt, updatedAt: '2026-01-02T00:00:00.000Z' });
  });

  it('closes, lists most recently updated first, and deletes', () => {
    const a = saveCase({ ioc, workflowId: null, analysis: null, draft: { ...emptyDraft(), title: 'A' } }, new Date('2026-01-01')).saved;
    saveCase({ ioc, workflowId: null, analysis: null, draft: { ...emptyDraft(), title: 'B' } }, new Date('2026-01-02'));
    setCaseStatus(a.id, 'closed', new Date('2026-01-03'));
    expect(loadCases().map(c => `${c.title}:${c.status}`)).toEqual(['A:closed', 'B:open']);
    expect(deleteCase(a.id).map(c => c.title)).toEqual(['B']);
  });
});

describe('case export', () => {
  it('renders a markdown note with verdict, actions and checklist', () => {
    const { saved } = saveCase({
      ioc, workflowId: 'ip-triage', analysis: null,
      draft: { ...emptyDraft(), title: 'Tor brute force', ticketRef: 'INC-123', verdict: 'likely_malicious', confidence: 'high',
        actionsTaken: ['Blocked indicator'], checklist: { 'Check reputation': true }, notes: 'Seen in SSH logs.' },
    });
    const md = caseToMarkdown(saved, workflow);
    expect(md).toContain('# Tor brute force');
    expect(md).toContain('| Verdict | Likely malicious (high confidence) |');
    expect(md).toContain('- Blocked indicator');
    expect(md).toContain('- [x] Check reputation');
    expect(md).toContain('- [ ] Check internal logs');
    expect(caseFilename(saved, 'md')).toBe('inc-123.md');
  });

  it('fills internal search templates with the indicator', () => {
    expect(internalSearches(workflow, detectIoc('185.220.101.4'))).toEqual([{ label: 'Firewall', query: 'src_ip=185.220.101.4' }]);
  });
});
