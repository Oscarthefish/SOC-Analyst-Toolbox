import { describe, it, expect } from 'vitest';
import { isWorkflowEnabled, toolsForWorkflow } from './workflows';
import { detectIoc } from './detectIoc';
import workflowsData from '../data/workflows.json';
import type { Workflow } from '../types/workflow';
import type { Tool } from '../types/tool';

const workflows = workflowsData as Workflow[];
const applicable = (input: string) => workflows.filter(w => isWorkflowEnabled(w, detectIoc(input)).enabled).map(w => w.id);

describe('isWorkflowEnabled', () => {
  it('offers Email Header Review only for pasted headers', () => {
    expect(applicable('8.8.8.8')).not.toContain('email-header-review');
    expect(applicable('bob@example.com')).not.toContain('email-header-review');
    expect(applicable('Received: from a by b\nFrom: x@example.com\nSubject: hi')).toEqual(['email-header-review']);
  });

  it('matches by indicator type', () => {
    expect(applicable('8.8.8.8')).toContain('ip-triage');
    expect(applicable('d41d8cd98f00b204e9800998ecf8427e')).toContain('malware-hash');
    expect(applicable('d41d8cd98f00b204e9800998ecf8427e')).not.toContain('ip-triage');
  });

  it('lets domain workflows accept URLs', () => {
    expect(applicable('https://evil.example.com/login')).toContain('domain-triage');
  });

  it('offers nothing for unrecognised input', () => {
    expect(applicable('hello world')).toEqual([]);
  });
});

describe('toolsForWorkflow', () => {
  const wf = workflows.find(w => w.id === 'cve-context')!;
  const builtin = (id: string): Tool => ({
    id, name: id, category: 'x', description: '', inputTypes: ['cve'], workflows: [], urlTemplate: 'https://a.example/{{value}}',
    whyUse: '', lookFor: '', riskNote: '', submissionRisk: 'low', requiresAccount: 'none', tags: [],
  });
  const custom = (id: string, workflows: string[], inputTypes: Tool['inputTypes']): Tool => ({ ...builtin(id), workflows, inputTypes });

  it('lists the workflow tools first, then custom tools assigned to it for this indicator type', () => {
    const own = wf.toolIds.slice(0, 2).map(builtin);
    const tools = [custom('custom-a', ['cve-context'], ['cve']), ...own, custom('custom-b', ['ip-triage'], ['cve']),
      custom('custom-c', ['cve-context'], ['ipv4'])];
    expect(toolsForWorkflow(wf, tools, detectIoc('CVE-2024-3400')).map(t => t.id)).toEqual([...wf.toolIds.slice(0, 2), 'custom-a']);
  });
});
