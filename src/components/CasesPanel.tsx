import { useState } from 'react';
import type { CaseRecord } from '../types/case';
import type { Workflow } from '../types/workflow';
import { verdictLabel, setCaseStatus, deleteCase, caseToMarkdown, caseFilename, downloadText } from '../lib/cases';

interface Props {
  cases: CaseRecord[];
  workflows: Workflow[];
  onOpen: (c: CaseRecord) => void;
  onChange: (cases: CaseRecord[]) => void;
}

const VERDICT_TONE: Record<string, string> = {
  malicious: 'text-danger-fg',
  likely_malicious: 'text-high-fg',
  suspicious: 'text-warn-fg',
  inconclusive: 'text-fg-2',
  noise: 'text-fg-3',
  benign: 'text-ok-fg',
};

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
              <th className="px-4 py-2" />
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
                  <td className="px-4 py-2.5">
                    <code className="text-xs font-mono text-fg-2">{c.ioc.normalised}</code>
                    <p className="text-[11px] text-fg-4 uppercase">{c.ioc.type}</p>
                  </td>
                  <td className={`px-4 py-2.5 whitespace-nowrap ${VERDICT_TONE[c.verdict] ?? 'text-fg-4'}`}>
                    {verdictLabel(c.verdict)}
                    {c.confidence && <p className="text-[11px] text-fg-4">{c.confidence} confidence</p>}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-fg-3 tabular-nums whitespace-nowrap">
                    {wf ? `${done}/${wf.checklist.length}` : '—'}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-fg-3 whitespace-nowrap">{new Date(c.updatedAt).toLocaleString()}</td>
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
  );
}
