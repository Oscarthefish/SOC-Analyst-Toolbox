import type { Tool, SubmissionRisk, RequiresAccount } from '../types/tool';
import type { IocType } from '../types/ioc';

/** The add-tool form, as edited (tags as comma-separated text). */
export interface ToolFormState {
  name: string;
  category: string;
  description: string;
  urlTemplate: string;
  inputTypes: IocType[];
  workflows: string[];
  whyUse: string;
  lookFor: string;
  riskNote: string;
  submissionRisk: SubmissionRisk;
  requiresAccount: RequiresAccount;
  tags: string;
}

export const DEFAULT_TOOL_FORM: ToolFormState = {
  name: '',
  category: 'Custom',
  description: '',
  urlTemplate: '',
  inputTypes: [],
  workflows: [],
  whyUse: '',
  lookFor: '',
  riskNote: '',
  submissionRisk: 'low',
  requiresAccount: 'none',
  tags: '',
};

/** Matches the backend's id rule (routes/toolsConfig.ts). */
export const TOOL_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const ID_PREFIX = 'custom-';
const MAX_SLUG = 48; // leaves room for the prefix and a "-NN" de-duplication suffix within 64

export function slugify(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, MAX_SLUG).replace(/-$/, '');
}

/** A unique id the backend will accept, derived from the tool name. */
export function generateToolId(name: string, taken: Set<string>): string {
  const base = ID_PREFIX + (slugify(name) || 'tool');
  let id = base;
  let n = 2;
  while (taken.has(id)) id = `${base}-${n++}`;
  return id;
}

export function validateToolForm(form: ToolFormState): Record<string, string> {
  const errors: Record<string, string> = {};
  if (!form.name.trim()) errors.name = 'Name is required.';
  if (!form.urlTemplate.trim()) errors.urlTemplate = 'URL template is required.';
  else if (!/^https?:\/\//i.test(form.urlTemplate.trim())) errors.urlTemplate = 'Must start with https:// or http://';
  if (form.inputTypes.length === 0) errors.inputTypes = 'Select at least one IOC type.';
  return errors;
}

export function formToTool(form: ToolFormState, takenIds: Set<string>): Tool {
  return {
    id: generateToolId(form.name.trim(), takenIds),
    name: form.name.trim(),
    category: form.category,
    description: form.description.trim(),
    urlTemplate: form.urlTemplate.trim(),
    inputTypes: form.inputTypes,
    workflows: form.workflows,
    whyUse: form.whyUse.trim(),
    lookFor: form.lookFor.trim(),
    riskNote: form.riskNote.trim() || 'This is a custom tool.',
    submissionRisk: form.submissionRisk,
    requiresAccount: form.requiresAccount,
    tags: form.tags.split(',').map(t => t.trim()).filter(Boolean),
  };
}
