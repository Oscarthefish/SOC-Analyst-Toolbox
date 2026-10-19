import { useState, useCallback, useRef, useMemo } from 'react';
import { runEnrichment } from '../lib/apiClient';
import { parseBatchInput, topFinding, rowsToCsv, SEVERITY_ORDER, BATCH_LIMIT } from '../lib/batch';
import type { BatchRow } from '../lib/batch';
import { downloadText } from '../lib/cases';
import type { Severity } from '../types/enrichment';
import { countSeverities } from '../lib/severityMix';
import { RingGauge, SeverityDonut, SeverityLegend } from './charts';
import { IocTypeChip } from './IocTypeChip';

interface BatchTriagePanelProps {
  onInvestigate: (ioc: string) => void;
}

const CONCURRENCY = 5;

const SEV: Record<Severity, { dot: string; pill: string; label: string }> = {
  critical: { dot: 'bg-danger',       pill: 'bg-danger-bg text-danger-fg border-danger-line', label: 'Critical' },
  high:     { dot: 'bg-high',         pill: 'bg-high-bg text-high-fg border-high-line',       label: 'High' },
  medium:   { dot: 'bg-warn',         pill: 'bg-warn-bg text-warn-fg border-warn-line',       label: 'Medium' },
  low:      { dot: 'bg-c1',           pill: 'bg-c1-bg text-c1-fg border-line',                label: 'Low' },
  benign:   { dot: 'bg-ok',           pill: 'bg-ok-bg text-ok-fg border-ok-line',             label: 'Benign' },
  unknown:  { dot: 'bg-line-strong',  pill: 'bg-raised text-fg-2 border-line',                label: 'Inconclusive' },
};

type SortKey = 'severity' | 'indicator' | 'type' | 'sources';

/** Sort rank: finished rows by severity first, then in-flight, pending, failed, skipped. */
function severityRank(r: BatchRow): number {
  if (r.status === 'done' && r.severity) return SEVERITY_ORDER[r.severity];
  return { running: 6, pending: 7, error: 8, skipped: 9, done: 5 }[r.status];
}

function SortableTh({ k, sort, onSort, children, className = '' }: {
  k: SortKey;
  sort: { key: SortKey; dir: 1 | -1 };
  onSort: (k: SortKey) => void;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <th className={`font-normal px-3 py-2 ${className}`} aria-sort={sort.key === k ? (sort.dir === 1 ? 'ascending' : 'descending') : 'none'}>
      <button onClick={() => onSort(k)} className="inline-flex items-center gap-1 hover:text-fg-1">
        {children}
        <span className="text-[9px] w-2">{sort.key === k ? (sort.dir === 1 ? '▲' : '▼') : ''}</span>
      </button>
    </th>
  );
}

export function BatchTriagePanel({ onInvestigate }: BatchTriagePanelProps) {
  const [input, setInput] = useState('');
  const [rows, setRows] = useState<BatchRow[]>([]);
  const [running, setRunning] = useState(false);
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: 'severity', dir: 1 });
  const [filter, setFilter] = useState<Severity | 'all'>('all');
  const [stopped, setStopped] = useState(false);
  const stopRef = useRef(false);

  const preview = useMemo(() => parseBatchInput(input), [input]);
  const runnable = preview.rows.filter(r => r.status === 'pending').length;

  const updateRow = useCallback((id: string, update: Partial<BatchRow>) => {
    setRows(prev => prev.map(r => (r.id === id ? { ...r, ...update } : r)));
  }, []);

  const handleRun = useCallback(async () => {
    if (running || runnable === 0) return;
    const parsed = preview.rows;
    setRows(parsed);
    stopRef.current = false;
    setStopped(false);
    setRunning(true);

    const queue = parsed.filter(r => r.status === 'pending');
    let next = 0;
    async function worker() {
      while (next < queue.length && !stopRef.current) {
        const row = queue[next++]!;
        updateRow(row.id, { status: 'running' });
        try {
          const result = await runEnrichment({ ioc: { original: row.raw, normalised: row.normalised, type: row.type } });
          if (!result) {
            updateRow(row.id, { status: 'error', errorMsg: 'Backend unreachable' });
          } else {
            updateRow(row.id, {
              status: 'done',
              severity: result.overall.severity,
              confidence: result.overall.confidence,
              sources: {
                withData: result.results.filter(r => r.status === 'ok' || r.status === 'cached').length,
                total: result.results.length,
              },
              topFinding: topFinding(result.results),
            });
          }
        } catch (err) {
          updateRow(row.id, { status: 'error', errorMsg: err instanceof Error ? err.message : 'Failed' });
        }
      }
    }
    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, queue.length) }, worker));
    setRunning(false);
  }, [running, runnable, preview, updateRow]);

  const handleStop = () => { stopRef.current = true; setStopped(true); };
  const handleClear = () => { stopRef.current = true; setInput(''); setRows([]); setFilter('all'); };

  const finished = rows.filter(r => r.status === 'done' || r.status === 'error').length;
  const total = rows.filter(r => r.status !== 'skipped').length;
  const counts = useMemo(() => {
    const c: Partial<Record<Severity, number>> = {};
    for (const r of rows) if (r.status === 'done' && r.severity) c[r.severity] = (c[r.severity] ?? 0) + 1;
    return c;
  }, [rows]);

  const visible = useMemo(() => {
    const list = filter === 'all' ? rows : rows.filter(r => r.status === 'done' && r.severity === filter);
    const cmp = (a: BatchRow, b: BatchRow): number => {
      switch (sort.key) {
        case 'severity': return severityRank(a) - severityRank(b);
        case 'indicator': return a.normalised.localeCompare(b.normalised);
        case 'type': return a.type.localeCompare(b.type);
        case 'sources': return (b.sources?.withData ?? -1) - (a.sources?.withData ?? -1);
      }
    };
    return [...list].sort((a, b) => cmp(a, b) * sort.dir || a.normalised.localeCompare(b.normalised));
  }, [rows, filter, sort]);

  const mix = useMemo(() => countSeverities(rows.filter(r => r.status === 'done' && r.severity).map(r => r.severity!)), [rows]);
  const done = rows.filter(r => r.status === 'done').length;
  const severe = (counts.critical ?? 0) + (counts.high ?? 0);

  const toggleSort = (key: SortKey) =>
    setSort(s => (s.key === key ? { key, dir: s.dir === 1 ? -1 : 1 } : { key, dir: 1 }));

  return (
    <div className="space-y-4">
      <div className="wb-card p-4 space-y-3">
        <div className="flex items-baseline justify-between gap-3">
          <label htmlFor="batch-input" className="wb-label">Indicators</label>
          <span className="text-[11px] text-fg-4">One per line or comma-separated · up to {BATCH_LIMIT} · defanged input is fine</span>
        </div>
        <textarea
          id="batch-input"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) { e.preventDefault(); void handleRun(); } }}
          placeholder={'185.220.101.42\nevil-phishing[.]com\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nCVE-2024-3400'}
          className="w-full h-32 px-3 py-2.5 text-[13px] font-mono rounded-md border border-line-strong bg-surface text-fg-1 resize-y focus:outline-none focus:border-accent focus:ring-[3px] focus:ring-accent/15"
          disabled={running}
          spellCheck={false}
        />
        <div className="flex flex-wrap items-center gap-2">
          {running ? (
            <button onClick={handleStop} className="h-8 px-3.5 text-xs font-semibold rounded-md border border-line-strong bg-surface text-fg-1 hover:border-danger-line hover:text-danger-fg">
              Stop
            </button>
          ) : (
            <button
              onClick={() => void handleRun()}
              disabled={runnable === 0}
              className="h-8 px-3.5 text-xs font-semibold rounded-md bg-accent text-white hover:bg-accent-strong disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {runnable === 0 ? 'Run triage' : `Triage ${runnable} indicator${runnable === 1 ? '' : 's'}`}
            </button>
          )}
          {(rows.length > 0 || input) && !running && (
            <button onClick={handleClear} className="h-8 px-3 text-xs rounded-md text-fg-3 hover:text-fg-1">Clear</button>
          )}
          <span className="text-xs text-fg-4">
            {running
              ? `${finished} of ${total} done · ${CONCURRENCY} at a time`
              : input && `${preview.rows.length} found${preview.rows.length - runnable > 0 ? ` · ${preview.rows.length - runnable} not recognised` : ''}${preview.truncated ? ` · ${preview.truncated} over the limit ignored` : ''}`}
          </span>
          <span className="ml-auto text-[11px] text-fg-4 hidden sm:inline"><span className="kbd">⌘</span> <span className="kbd">↵</span> to run</span>
        </div>
      </div>

      {rows.length > 0 && (
        <div className="grid gap-3 sm:grid-cols-[auto_minmax(0,1fr)]">
          <section className="wb-card p-4 flex items-center gap-4">
            <RingGauge fraction={total ? finished / total : 0} tone="stroke-accent" size={72} thickness={8} label={`${finished} of ${total} finished`}>
              <span className="text-[13px] font-semibold text-fg-1 tabular-nums">{total ? Math.round((finished / total) * 100) : 0}%</span>
            </RingGauge>
            <div>
              <p className="text-[13px] font-medium text-fg-1">{running ? 'Running' : 'Finished'}</p>
              <p className="text-[11px] text-fg-4">{finished} of {total} indicators</p>
            </div>
          </section>
          <section className="wb-card p-4 flex items-center gap-4 min-w-0">
            <SeverityDonut mix={mix} label="Triage results by severity" size={72} thickness={10}>
              <span className="text-[15px] font-semibold text-fg-1 tabular-nums">{done}</span>
            </SeverityDonut>
            <div className="min-w-0">
              <p className="text-[13px] font-medium text-fg-1">
                {severe > 0 ? <><span className="text-danger-fg">{severe}</span> high or critical</> : done ? 'Nothing high or critical' : 'Waiting for results'}
              </p>
              <div className="mt-1.5"><SeverityLegend mix={mix} /></div>
            </div>
          </section>
        </div>
      )}

      {rows.length > 0 && (
        <div className="wb-card overflow-hidden">
          <div className="flex flex-wrap items-center gap-2 px-4 py-3 border-b border-line">
            <div role="tablist" className="flex flex-wrap gap-1">
              <button role="tab" aria-selected={filter === 'all'} onClick={() => setFilter('all')}
                className={`h-7 px-2.5 rounded-md text-xs ${filter === 'all' ? 'bg-selected text-selected-fg font-medium' : 'text-fg-3 hover:text-fg-1'}`}>
                All {rows.length}
              </button>
              {(Object.keys(SEV) as Severity[]).filter(s => counts[s]).map(s => (
                <button key={s} role="tab" aria-selected={filter === s} onClick={() => setFilter(s)}
                  className={`h-7 px-2.5 rounded-md text-xs inline-flex items-center gap-1.5 ${filter === s ? 'bg-selected text-selected-fg font-medium' : 'text-fg-3 hover:text-fg-1'}`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${SEV[s].dot}`} />{SEV[s].label} {counts[s]}
                </button>
              ))}
            </div>
            {running && (
              <div className="flex-1 min-w-[120px] max-w-[240px] h-1 rounded-full bg-raised overflow-hidden" aria-label="Progress">
                <div className="h-full bg-accent transition-all" style={{ width: `${total ? (finished / total) * 100 : 0}%` }} />
              </div>
            )}
            <button
              onClick={() => downloadText(`batch-triage-${new Date().toISOString().slice(0, 10)}.csv`, rowsToCsv(visible), 'text/csv')}
              disabled={finished === 0}
              className="ml-auto h-8 px-2.5 text-xs font-medium rounded-md border border-line bg-surface text-fg-2 hover:border-line-strong disabled:opacity-40"
            >
              Export CSV
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-[13px]">
              <thead>
                <tr className="text-[11px] text-fg-4 border-b border-line bg-inset">
                  <SortableTh k="severity" sort={sort} onSort={toggleSort} className="sticky left-0 bg-inset w-[130px]">Severity</SortableTh>
                  <SortableTh k="indicator" sort={sort} onSort={toggleSort}>Indicator</SortableTh>
                  <SortableTh k="type" sort={sort} onSort={toggleSort}>Type</SortableTh>
                  <SortableTh k="sources" sort={sort} onSort={toggleSort}>Sources</SortableTh>
                  <th className="font-normal px-3 py-2">Top finding</th>
                  <th className="px-3 py-2"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line-soft">
                {visible.map(row => {
                  const sev = row.severity ? SEV[row.severity] : null;
                  return (
                    <tr key={row.id} className={`group hover:bg-inset ${row.status === 'skipped' ? 'text-fg-4' : ''}`}>
                      <td className="sticky left-0 bg-surface group-hover:bg-inset px-3 py-2 whitespace-nowrap">
                        {row.status === 'done' && sev ? (
                          <span className={`inline-flex items-center gap-1.5 h-[22px] px-2 rounded-full border text-[11px] font-medium ${sev.pill}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${sev.dot}`} />{sev.label}
                          </span>
                        ) : row.status === 'running' ? (
                          <span className="inline-flex items-center gap-2 text-xs text-fg-3">
                            <span className="w-3 h-3 rounded-full border-2 border-line border-t-accent animate-spin" />Running
                          </span>
                        ) : row.status === 'error' ? (
                          <span className="text-xs text-danger-fg">Failed</span>
                        ) : row.status === 'skipped' ? (
                          <span className="text-xs">Not recognised</span>
                        ) : (
                          <span className="text-xs text-fg-4">{stopped && !running ? 'Not run' : 'Queued'}</span>
                        )}
                        {row.confidence && <p className="mt-0.5 text-[11px] text-fg-4">{row.confidence} confidence</p>}
                      </td>
                      <td className="px-3 py-2 max-w-[340px]">
                        <code className="font-mono text-xs text-fg-1 break-all">{row.normalised}</code>
                      </td>
                      <td className="px-3 py-2 whitespace-nowrap">{row.type === 'unknown' ? <span className="text-xs text-fg-4">—</span> : <IocTypeChip type={row.type} size="sm" />}</td>
                      <td className="px-3 py-2 text-xs text-fg-3 tabular-nums whitespace-nowrap">
                        {row.sources && (
                          <span className="flex items-center gap-2" title={`${row.sources.withData} of ${row.sources.total} sources returned data`}>
                            <span className="w-10 h-1.5 rounded-full bg-raised overflow-hidden">
                              <span className="block h-full rounded-full bg-c1" style={{ width: `${(row.sources.withData / Math.max(1, row.sources.total)) * 100}%` }} />
                            </span>
                            {row.sources.withData}/{row.sources.total}
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-2 text-xs text-fg-2 max-w-[420px]">
                        <span className="line-clamp-2">{row.errorMsg ?? row.topFinding ?? ''}</span>
                      </td>
                      <td className="px-3 py-2 text-right">
                        {row.status !== 'skipped' && (
                          <button
                            onClick={() => onInvestigate(row.normalised)}
                            className="h-7 px-2 text-xs rounded-md border border-line bg-surface text-fg-2 hover:border-accent hover:text-accent-fg whitespace-nowrap"
                          >
                            Investigate
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
