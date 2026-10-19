import { describe, it, expect } from 'vitest';
import { isWorkflowEnabled } from './workflows';
import { detectIoc } from './detectIoc';
import workflowsData from '../data/workflows.json';
import type { Workflow } from '../types/workflow';

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
