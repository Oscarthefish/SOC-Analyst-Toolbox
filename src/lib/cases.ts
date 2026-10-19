import type { CaseRecord, CaseDraft, CaseVerdict, CaseConfidence } from '../types/case';
import type { AnalysisResponse } from '../types/analysis';
import type { IocInput } from '../types/enrichment';
import type { Workflow } from '../types/workflow';
import type { DetectedIoc } from '../types/ioc';
import { applyTemplate, buildTemplateVars } from './template';

const STORAGE_KEY = 'soc-toolbox-cases-v2';

export const VERDICT_OPTIONS: { value: CaseVerdict; label: string }[] = [
  { value: 'malicious', label: 'Malicious' },
  { value: 'likely_malicious', label: 'Likely malicious' },
  { value: 'suspicious', label: 'Suspicious' },
  { value: 'inconclusive', label: 'Inconclusive' },
  { value: 'noise', label: 'Scanner / noise' },
  { value: 'benign', label: 'Benign' },
];

export const CONFIDENCE_OPTIONS: CaseConfidence[] = ['low', 'medium', 'high'];

export const ACTION_OPTIONS = [
  'Blocked indicator',
  'Quarantined email',
  'Isolated endpoint',
  'Reset password',
  'Revoked sessions',
  'Requested takedown',
  'Tuned detection',
  'Escalated',
  'Monitoring only',
];

export function verdictLabel(v: CaseVerdict | ''): string {
  return VERDICT_OPTIONS.find(o => o.value === v)?.label ?? 'No verdict';
}

export function emptyDraft(): CaseDraft {
  return { title: '', ticketRef: '', verdict: '', confidence: '', actionsTaken: [], checklist: {}, notes: '' };
}

// ── Storage ────────────────────────────────────────────────────────────────

export function loadCases(): CaseRecord[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    const cases = raw ? (JSON.parse(raw) as CaseRecord[]) : [];
    return cases.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  } catch {
    return [];
  }
}

function persist(cases: CaseRecord[]): CaseRecord[] {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(cases));
  } catch (err) {
    console.error('[cases] Failed to save cases:', err);
  }
  return cases.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
}

function newId(): string {
  return typeof crypto !== 'undefined' && 'randomUUID' in crypto
    ? crypto.randomUUID()
    : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

/** Create a case, or update it when `id` matches an existing one. Returns the saved case and the full list. */
export function saveCase(
  input: { id?: string; ioc: IocInput; workflowId: string | null; analysis: AnalysisResponse | null; draft: CaseDraft },
  now = new Date(),
): { saved: CaseRecord; cases: CaseRecord[] } {
  const cases = loadCases();
  const existing = input.id ? cases.find(c => c.id === input.id) : undefined;
  const ts = now.toISOString();
  const saved: CaseRecord = {
    id: existing?.id ?? newId(),
    status: existing?.status ?? 'open',
    createdAt: existing?.createdAt ?? ts,
    updatedAt: ts,
    ioc: input.ioc,
    workflowId: input.workflowId,
    analysis: input.analysis ?? existing?.analysis ?? null,
    ...input.draft,
    title: input.draft.title.trim() || input.ioc.normalised,
  };
  const next = existing ? cases.map(c => (c.id === saved.id ? saved : c)) : [saved, ...cases];
  return { saved, cases: persist(next) };
}

export function setCaseStatus(id: string, status: CaseRecord['status'], now = new Date()): CaseRecord[] {
  return persist(loadCases().map(c => (c.id === id ? { ...c, status, updatedAt: now.toISOString() } : c)));
}

export function deleteCase(id: string): CaseRecord[] {
  return persist(loadCases().filter(c => c.id !== id));
}

// ── Export ─────────────────────────────────────────────────────────────────

/** Fill a workflow's internal search templates for this indicator. */
export function internalSearches(workflow: Workflow, ioc: DetectedIoc): { label: string; query: string }[] {
  const vars = buildTemplateVars(ioc);
  return workflow.internalSearches.map(s => ({ label: s.label, query: applyTemplate(s.template, vars) }));
}

/** Markdown case note for tickets and handovers. */
export function caseToMarkdown(c: CaseRecord, workflow?: Workflow): string {
  const lines: string[] = [
    `# ${c.title}`,
    '',
    `| | |`,
    `|---|---|`,
    `| Indicator | \`${c.ioc.normalised}\` (${c.ioc.type}) |`,
    `| Ticket | ${c.ticketRef || '—'} |`,
    `| Status | ${c.status === 'open' ? 'Open' : 'Closed'} |`,
    `| Verdict | ${verdictLabel(c.verdict)}${c.confidence ? ` (${c.confidence} confidence)` : ''} |`,
    `| Workflow | ${workflow?.name ?? '—'} |`,
    `| Updated | ${c.updatedAt} |`,
  ];

  if (c.actionsTaken.length) lines.push('', '## Actions taken', ...c.actionsTaken.map(a => `- ${a}`));
  if (c.notes.trim()) lines.push('', '## Notes', c.notes.trim());

  if (workflow?.checklist.length) {
    lines.push('', '## Checklist', ...workflow.checklist.map(item => `- [${c.checklist[item] ? 'x' : ' '}] ${item}`));
  }

  if (c.analysis) {
    const a = c.analysis;
    const withData = a.results.filter(r => r.status === 'ok' || r.status === 'cached');
    lines.push(
      '',
      '## Enrichment',
      `Severity **${a.overall.severity}**, ${a.overall.confidence} confidence, ${withData.length}/${a.results.length} sources returned data (analysed ${a.analysedAt}).`,
      '',
      ...withData.map(r => `- **${r.providerName}**: ${r.summary}`),
    );
    if (a.contradictions?.length) lines.push('', '**Source conflicts**', ...a.contradictions.map(x => `- ${x.message}`));
  }

  return lines.join('\n') + '\n';
}

export function caseToJson(c: CaseRecord): string {
  return JSON.stringify({ format: 'soc-toolbox-case', version: 2, case: c }, null, 2);
}

/** Trigger a browser download of text content. */
export function downloadText(filename: string, content: string, type: string): void {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1_000);
}

export function caseFilename(c: CaseRecord, ext: string): string {
  const slug = (c.ticketRef || c.title).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60) || 'case';
  return `${slug}.${ext}`;
}
