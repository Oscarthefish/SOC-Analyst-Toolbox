import { useEffect, useMemo, useState } from 'react';
import type { DetectedIoc } from '../types/ioc';
import type { Workflow } from '../types/workflow';
import type { AnalysisResponse } from '../types/analysis';
import type { CaseRecord, CaseDraft } from '../types/case';
import {
  VERDICT_OPTIONS, CONFIDENCE_OPTIONS, ACTION_OPTIONS, emptyDraft, saveCase,
  internalSearches, caseToMarkdown, caseToJson, caseFilename, downloadText,
} from '../lib/cases';
import { CopyButton } from './CopyButton';

interface Props {
  ioc: DetectedIoc;
  workflow: Workflow | null;
  analysis: AnalysisResponse | null;
  activeCase: CaseRecord | null;
  onSaved: (saved: CaseRecord, cases: CaseRecord[]) => void;
}

function draftFrom(c: CaseRecord | null): CaseDraft {
  if (!c) return emptyDraft();
  const { title, ticketRef, verdict, confidence, actionsTaken, checklist, notes } = c;
  return { title, ticketRef, verdict, confidence, actionsTaken, checklist, notes };
}

const inputCls = 'w-full h-8 px-2.5 rounded-md border border-line-strong bg-surface text-[13px] text-fg-1 focus:outline-none focus:border-accent focus:ring-[3px] focus:ring-accent/15';

function Segmented<T extends string>({ options, value, onChange, label }: {
  options: { value: T; label: string }[];
  value: T | '';
  onChange: (v: T | '') => void;
  label: string;
}) {
  return (
    <div role="radiogroup" aria-label={label} className="flex flex-wrap gap-1">
      {options.map(o => {
        const on = value === o.value;
        return (
          <button
            key={o.value}
            role="radio"
            aria-checked={on}
            onClick={() => onChange(on ? '' : o.value)}
            className={`h-7 px-2.5 rounded-md border text-xs transition-colors ${
              on ? 'bg-accent-bg border-accent-line text-accent-fg font-medium' : 'bg-surface border-line text-fg-2 hover:border-line-strong'
            }`}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

function Field({ label, children, aside }: { label: string; children: React.ReactNode; aside?: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-baseline justify-between">
        <p className="text-xs font-medium text-fg-2">{label}</p>
        {aside}
      </div>
      {children}
    </div>
  );
}

/** Verdict, notes, checklist and internal searches for the indicator under investigation. */
export function CaseWorkspace({ ioc, workflow, analysis, activeCase, onSaved }: Props) {
  const [draft, setDraft] = useState<CaseDraft>(() => draftFrom(activeCase));
  const [justSaved, setJustSaved] = useState(false);

  // Load the case when it changes; start a fresh draft when the indicator changes without one
  useEffect(() => { setDraft(draftFrom(activeCase)); }, [activeCase?.id]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { if (!activeCase) setDraft(emptyDraft()); }, [ioc.normalised]); // eslint-disable-line react-hooks/exhaustive-deps

  const dirty = useMemo(
    () => JSON.stringify(draft) !== JSON.stringify(draftFrom(activeCase)),
    [draft, activeCase],
  );
  const searches = useMemo(() => (workflow ? internalSearches(workflow, ioc) : []), [workflow, ioc]);
  const checklist = workflow?.checklist ?? [];
  const doneCount = checklist.filter(i => draft.checklist[i]).length;

  const update = (patch: Partial<CaseDraft>) => setDraft(d => ({ ...d, ...patch }));

  function handleSave() {
    const { saved, cases } = saveCase({
      id: activeCase?.id,
      ioc: { original: ioc.original, normalised: ioc.normalised, type: ioc.type },
      workflowId: workflow?.id ?? activeCase?.workflowId ?? null,
      analysis: analysis ?? activeCase?.analysis ?? null,
      draft,
    });
    onSaved(saved, cases);
    setJustSaved(true);
    setTimeout(() => setJustSaved(false), 1500);
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 's') {
      e.preventDefault();
      handleSave();
    }
  }

  return (
    <div className="wb-card" onKeyDown={handleKeyDown}>
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 border-b border-line">
        <div className="flex items-baseline gap-2.5">
          <h2 className="wb-label">Case</h2>
          <span className="text-[11px] text-fg-4">
            {!activeCase ? 'Not saved'
              : `${activeCase.status === 'open' ? 'Open' : 'Closed'} · saved ${new Date(activeCase.updatedAt).toLocaleString()}`}
            {activeCase && dirty && <span className="text-warn-fg"> · unsaved changes</span>}
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          {activeCase && (
            <>
              <button
                onClick={() => downloadText(caseFilename(activeCase, 'md'), caseToMarkdown(activeCase, workflow ?? undefined), 'text/markdown')}
                className="h-8 px-2.5 text-xs font-medium rounded-md border border-line bg-surface text-fg-2 hover:border-line-strong"
              >
                Export .md
              </button>
              <button
                onClick={() => downloadText(caseFilename(activeCase, 'json'), caseToJson(activeCase), 'application/json')}
                className="h-8 px-2.5 text-xs font-medium rounded-md border border-line bg-surface text-fg-2 hover:border-line-strong"
              >
                Export .json
              </button>
            </>
          )}
          <button
            onClick={handleSave}
            disabled={!!activeCase && !dirty}
            title="⌘S"
            className="h-8 px-3.5 text-xs font-semibold rounded-md bg-accent text-white hover:bg-accent-strong disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {justSaved ? 'Saved' : activeCase ? 'Save changes' : 'Save case'}
          </button>
        </div>
      </div>

      <div className="grid lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] divide-y lg:divide-y-0 lg:divide-x divide-line">
        {/* Assessment */}
        <div className="p-4 space-y-4">
          <div className="grid sm:grid-cols-2 gap-3">
            <Field label="Title">
              <input className={inputCls} value={draft.title} placeholder={ioc.normalised} onChange={e => update({ title: e.target.value })} />
            </Field>
            <Field label="Ticket reference">
              <input className={inputCls} value={draft.ticketRef} placeholder="INC-1234" onChange={e => update({ ticketRef: e.target.value })} />
            </Field>
          </div>

          <Field label="Verdict" aside={analysis && <span className="text-[11px] text-fg-4">Enrichment says <span className="capitalize">{analysis.overall.severity}</span></span>}>
            <Segmented label="Verdict" options={VERDICT_OPTIONS} value={draft.verdict} onChange={v => update({ verdict: v })} />
          </Field>

          <Field label="Confidence">
            <Segmented
              label="Confidence"
              options={CONFIDENCE_OPTIONS.map(c => ({ value: c, label: c[0]!.toUpperCase() + c.slice(1) }))}
              value={draft.confidence}
              onChange={v => update({ confidence: v })}
            />
          </Field>

          <Field label="Actions taken">
            <div className="flex flex-wrap gap-1">
              {ACTION_OPTIONS.map(a => {
                const on = draft.actionsTaken.includes(a);
                return (
                  <button
                    key={a}
                    aria-pressed={on}
                    onClick={() => update({ actionsTaken: on ? draft.actionsTaken.filter(x => x !== a) : [...draft.actionsTaken, a] })}
                    className={`h-7 px-2.5 rounded-md border text-xs transition-colors ${
                      on ? 'bg-raised border-line-strong text-fg-1 font-medium' : 'bg-surface border-line text-fg-3 hover:text-fg-1'
                    }`}
                  >
                    {on && '✓ '}{a}
                  </button>
                );
              })}
            </div>
          </Field>

          <Field label="Notes">
            <textarea
              rows={4}
              value={draft.notes}
              onChange={e => update({ notes: e.target.value })}
              placeholder="What you checked, what you found, and why you reached the verdict."
              className="w-full px-2.5 py-2 rounded-md border border-line-strong bg-surface text-[13px] text-fg-1 leading-relaxed resize-y focus:outline-none focus:border-accent focus:ring-[3px] focus:ring-accent/15"
            />
          </Field>
        </div>

        {/* Workflow guidance */}
        <div className="p-4 space-y-5">
          {!workflow ? (
            <p className="text-xs text-fg-4">Choose a workflow above to get its analyst checklist and pre-filled internal search queries.</p>
          ) : (
            <>
              <Field label={`${workflow.name} checklist`} aside={<span className="text-[11px] text-fg-4 tabular-nums">{doneCount}/{checklist.length}</span>}>
                <ul className="space-y-1">
                  {checklist.map(item => (
                    <li key={item}>
                      <label className="flex items-start gap-2.5 text-[13px] text-fg-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={!!draft.checklist[item]}
                          onChange={e => update({ checklist: { ...draft.checklist, [item]: e.target.checked } })}
                          className="mt-[3px] accent-[var(--color-accent)]"
                        />
                        <span className={draft.checklist[item] ? 'text-fg-4 line-through' : ''}>{item}</span>
                      </label>
                    </li>
                  ))}
                </ul>
              </Field>

              {searches.length > 0 && (
                <Field label="Internal searches">
                  <div className="border border-line rounded-md divide-y divide-line-soft">
                    {searches.map(s => (
                      <div key={s.label} className="flex items-center gap-3 px-2.5 py-1.5">
                        <span className="w-36 shrink-0 text-xs text-fg-3 truncate">{s.label}</span>
                        <code className="flex-1 min-w-0 text-[11px] font-mono text-fg-1 truncate" title={s.query}>{s.query}</code>
                        <CopyButton text={s.query} label="query" iconOnly />
                      </div>
                    ))}
                  </div>
                </Field>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
