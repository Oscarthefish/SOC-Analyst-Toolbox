import { useState } from 'react';
import type { CaseRecord, CaseVerdict } from '../types/case';
import type { Workflow } from '../types/workflow';
import { verdictLabel, setCaseStatus, deleteCase, caseToMarkdown, caseFilename, downloadText } from '../lib/cases';
import { RingGauge } from './charts';
import { IocTypeChip } from './IocTypeChip';

interface Props {
  cases: CaseRecord[];
  workflows: Workflow[];
  onOpen: (c: CaseRecord) => void;
  onChange: (cases: CaseRecord[]) => void;
}

const VERDICTS: (CaseVerdict | '')[] = ['malicious', 'likely_malicious', 'suspicious', 'inconclusive', 'noise', 'benign', ''];

const VERDICT_PILL: Record<string, string> = {
  malicious: 'bg-danger-bg text-danger-fg border-danger-line',
  likely_malicious: 'bg-high-bg text-high-fg border-high-line',
  suspicious: 'bg-warn-bg text-warn-fg border-warn-line',
  inconclusive: 'bg-raised text-fg-2 border-line',
  noise: 'bg-c1-bg text-c1-fg border-line',
  benign: 'bg-ok-bg text-ok-fg border-ok-line',
  '': 'bg-surface text-fg-4 border-line border-dashed',
};

const VERDICT_BAR: Record<string, string> = {
  malicious: 'bg-danger', likely_malicious: 'bg-high', suspicious: 'bg-warn',
  inconclusive: 'bg-line-strong', noise: 'bg-c1', benign: 'bg-ok', '': 'bg-line',
};

function CasesSummary({ cases, workflows }: { cases: CaseRecord[]; workflows: Workflow[] }) {
  const open = cases.filter(c => c.status === 'open').length;
  const counts = VERDICTS.map(v => [v, cases.filter(c => c.verdict === v).length] as const).filter(([, n]) => n > 0);
  let steps = 0, done = 0;
  for (const c of cases.filter(x => x.status === 'open')) {
    const wf = workflows.find(w => w.id === c.workflowId);
    if (!wf) continue;
    steps += wf.checklist.length;
    done += wf.checklist.filter(i => c.checklist[i]).length;
  }

  return (
    <div className="grid gap-3 md:grid-cols-[auto_minmax(0,1fr)_auto]">
      <section className="wb-card p-4 flex items-center gap-4">
        <RingGauge fraction={cases.length ? open / cases.length : 0} tone="stroke-c1" size={72} thickness={8} label={`${open} of ${cases.length} cases open`}>
          <span className="text-[18px] font-semibold text-fg-1 tabular-nums">{open}</span>
        </RingGauge>
        <div>
          <p className="text-[13px] font-medium text-fg-1">Open cases</p>
          <p className="text-[11px] text-fg-4">{cases.length - open} closed · {cases.length} total</p>
        </div>
      </section>

      <section className="wb-card p-4 min-w-0">
        <h2 className="wb-label mb-2.5">Verdicts</h2>
        <div className="flex h-2.5 gap-[2px] rounded-full overflow-hidden bg-raised" role="img"
          aria-label={counts.map(([v, n]) => `${n} ${verdictLabel(v).toLowerCase()}`).join(', ')}>
          {counts.map(([v, n]) => <span key={v || 'none'} className={VERDICT_BAR[v]} style={{ flexGrow: n, flexBasis: 0 }} />)}
        </div>
        <ul className="mt-2.5 flex flex-wrap gap-x-3 gap-y-1">
          {counts.map(([v, n]) => (
            <li key={v || 'none'} className="flex items-center gap-1.5 text-[11px] text-fg-3">
              <span className={`w-2 h-2 rounded-sm ${VERDICT_BAR[v]}`} aria-hidden />
              {verdictLabel(v)} <span className="text-fg-1 font-medium tabular-nums">{n}</span>
            </li>
          ))}
        </ul>
      </section>

      <section className="wb-card p-4 flex items-center gap-4">
        <RingGauge fraction={steps ? done / steps : 0} tone="stroke-ok" size={72} thickness={8} label={`${done} of ${steps} checklist steps done on open cases`}>
          <span className="text-[13px] font-semibold text-fg-1 tabular-nums">{steps ? Math.round((done / steps) * 100) : 0}%</span>
        </RingGauge>
        <div>
          <p className="text-[13px] font-medium text-fg-1">Checklists</p>
          <p className="text-[11px] text-fg-4">{done} of {steps} steps on open cases</p>
        </div>
      </section>
    </div>
  );
}

type Filter = 'open' | 'closed' | 'all';

export function CasesPanel({ cases, workflows, onOpen, onChange }: Props) {
  const [filter, setFilter] = useState<Filter>('open');
  const [query, setQuery] = useState('');
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  const q = query.trim().toLowerCase();
  const visible = cases.filter(c =>
    (filter === 'all' || c.status === filter) &&
    (!q || [c.title, c.ticketRef, c.ioc.normalised, c.notes].some(f => f.toLowerCase().includes(q))),
  );
  const counts = { open: cases.filter(c => c.status === 'open').length, closed: cases.filter(c => c.status === 'closed').length };

  if (cases.length === 0) {
    return (
      <div className="wb-card px-6 py-10 text-center">
        <p className="text-[13px] font-medium text-fg-1">No cases yet</p>
        <p className="text-xs text-fg-3 mt-1 max-w-sm mx-auto">
          Investigate an indicator, record a verdict and notes in the Case panel, and save it. Cases are stored in this browser.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
    <CasesSummary cases={cases} workflows={workflows} />
    <div className="wb-card overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 px-4 py-3 border-b border-line">
        <div role="tablist" className="flex gap-1">
          {(['open', 'closed', 'all'] as Filter[]).map(f => (
            <button
              key={f}
              role="tab"
              aria-selected={filter === f}
              onClick={() => setFilter(f)}
              className={`h-7 px-2.5 rounded-md text-xs ${filter === f ? 'bg-raised text-fg-1 font-medium' : 'text-fg-3 hover:text-fg-1'}`}
            >
              {f === 'open' ? `Open ${counts.open}` : f === 'closed' ? `Closed ${counts.closed}` : `All ${cases.length}`}
            </button>
          ))}
        </div>
        <input
          type="search"
          value={query}
          onChange={e => setQuery(e.target.value)}
          placeholder="Search title, ticket, indicator, notes"
          className="ml-auto w-full sm:w-72 h-8 px-2.5 rounded-md border border-line-strong bg-surface text-[13px] focus:outline-none focus:border-accent"
        />
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-[13px]">
          <thead>
            <tr className="text-[11px] text-fg-4 border-b border-line bg-inset">
              <th className="font-normal px-4 py-2">Case</th>
              <th className="font-normal px-4 py-2">Indicator</th>
              <th className="font-normal px-4 py-2">Verdict</th>
              <th className="font-normal px-4 py-2">Checklist</th>
              <th className="font-normal px-4 py-2">Updated</th>
              <th className="px-4 py-2"><span className="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line-soft">
            {visible.map(c => {
              const wf = workflows.find(w => w.id === c.workflowId);
              const done = wf ? wf.checklist.filter(i => c.checklist[i]).length : 0;
              return (
                <tr key={c.id} className="hover:bg-inset align-top">
                  <td className="px-4 py-2.5 max-w-[260px]">
                    <button onClick={() => onOpen(c)} className="font-medium text-fg-1 hover:text-accent-fg text-left truncate max-w-full block">
                      {c.title}
                    </button>
                    <p className="text-[11px] text-fg-4">
                      {c.ticketRef || 'No ticket'}{c.status === 'closed' && ' · closed'}
                    </p>
                  </td>
                  <td className="px-4 py-2.5 max-w-[280px]">
                    <div className="flex items-center gap-2 min-w-0">
                      <IocTypeChip type={c.ioc.type === 'unknown' && c.ioc.normalised.includes('\n') ? 'headers' : c.ioc.type} size="sm" />
                      <code className="block text-xs font-mono text-fg-2 truncate" title={c.ioc.normalised}>{c.ioc.normalised.split('\n')[0]}</code>
                    </div>
                  </td>
                  <td className="px-4 py-2.5 whitespace-nowrap">
                    <span className={`inline-flex items-center h-[22px] px-2 rounded-full border text-[11px] font-medium ${VERDICT_PILL[c.verdict] ?? VERDICT_PILL['']}`}>
                      {verdictLabel(c.verdict)}
                    </span>
                    {c.confidence && <p className="mt-0.5 text-[11px] text-fg-4">{c.confidence} confidence</p>}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-fg-3 tabular-nums whitespace-nowrap">
                    {wf ? (
                      <span className="flex items-center gap-2">
                        <span className="w-14 h-1.5 rounded-full bg-raised overflow-hidden">
                          <span className="block h-full rounded-full bg-ok" style={{ width: `${(done / Math.max(1, wf.checklist.length)) * 100}%` }} />
                        </span>
                        {done}/{wf.checklist.length}
                      </span>
                    ) : '—'}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-fg-3 whitespace-nowrap">{new Date(c.updatedAt).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}</td>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center justify-end gap-1 whitespace-nowrap">
                      {confirmDelete === c.id ? (
                        <>
                          <span className="text-xs text-danger-fg mr-1">Delete this case?</span>
                          <button onClick={() => { onChange(deleteCase(c.id)); setConfirmDelete(null); }} className="h-7 px-2 text-xs rounded-md bg-danger text-white">Delete</button>
                          <button onClick={() => setConfirmDelete(null)} className="h-7 px-2 text-xs rounded-md border border-line text-fg-2">Cancel</button>
                        </>
                      ) : (
                        <>
                          <button onClick={() => onOpen(c)} className="h-7 px-2 text-xs rounded-md border border-line bg-surface text-fg-2 hover:border-line-strong">Open</button>
                          <button
                            onClick={() => downloadText(caseFilename(c, 'md'), caseToMarkdown(c, wf), 'text/markdown')}
                            className="h-7 px-2 text-xs rounded-md text-fg-3 hover:text-fg-1"
                          >
                            Export
                          </button>
                          <button
                            onClick={() => onChange(setCaseStatus(c.id, c.status === 'open' ? 'closed' : 'open'))}
                            className="h-7 px-2 text-xs rounded-md text-fg-3 hover:text-fg-1"
                          >
                            {c.status === 'open' ? 'Close' : 'Reopen'}
                          </button>
                          <button onClick={() => setConfirmDelete(c.id)} className="h-7 px-2 text-xs rounded-md text-fg-4 hover:text-danger-fg">
                            Delete
                          </button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
            {visible.length === 0 && (
              <tr><td colSpan={6} className="px-4 py-6 text-xs text-fg-4">No cases match.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
    </div>
  );
}
