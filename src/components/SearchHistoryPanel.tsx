import { useMemo } from 'react';
import type { HistoryEntry } from '../lib/searchHistory';
import { countSeverities } from '../lib/severityMix';
import { lastSevenDays } from '../lib/activity';
import { SeverityDonut, SeverityLegend, SeverityColumns } from './charts';
import { IocTypeChip, IOC_TYPE_LABEL, iocTypeDot } from './IocTypeChip';

interface SearchHistoryPanelProps {
  entries: HistoryEntry[];
  onLoad: (entry: HistoryEntry) => void;
  onRemove: (id: string) => void;
  onClear: () => void;
}

const SEV_STYLES: Record<string, { bg: string; text: string; border: string; dot: string; rule: string }> = {
  critical: { bg: 'bg-danger-bg', text: 'text-danger-fg', border: 'border-danger-line', dot: 'bg-danger', rule: 'border-l-danger' },
  high:     { bg: 'bg-high-bg',   text: 'text-high-fg',   border: 'border-high-line',   dot: 'bg-high',   rule: 'border-l-high' },
  medium:   { bg: 'bg-warn-bg',   text: 'text-warn-fg',   border: 'border-warn-line',   dot: 'bg-warn',   rule: 'border-l-warn' },
  low:      { bg: 'bg-c1-bg',     text: 'text-c1-fg',     border: 'border-line',        dot: 'bg-c1',     rule: 'border-l-c1' },
  benign:   { bg: 'bg-ok-bg',     text: 'text-ok-fg',     border: 'border-ok-line',     dot: 'bg-ok',     rule: 'border-l-ok' },
  unknown:  { bg: 'bg-raised',    text: 'text-fg-2',      border: 'border-line',        dot: 'bg-fg-4',   rule: 'border-l-line-strong' },
};

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60_000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d === 1) return 'yesterday';
  return `${d}d ago`;
}

function ClockIcon() {
  return (
    <svg className="w-10 h-10 text-fg-4" fill="none" stroke="currentColor" strokeWidth={1.4} viewBox="0 0 24 24">
      <circle cx="12" cy="12" r="10" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6l4 2" />
    </svg>
  );
}

function HistorySummary({ entries }: { entries: HistoryEntry[] }) {
  const mix = useMemo(() => countSeverities(entries.map(e => e.result.overall.severity)), [entries]);
  const columns = useMemo(() => lastSevenDays(entries), [entries]);
  const types = useMemo(() => {
    const counts = new Map<string, number>();
    for (const e of entries) counts.set(e.ioc.type, (counts.get(e.ioc.type) ?? 0) + 1);
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }, [entries]);
  const maxType = Math.max(1, ...types.map(t => t[1]));

  return (
    <div className="grid gap-3 md:grid-cols-3">
      <section className="wb-card p-4 flex items-center gap-4">
        <SeverityDonut mix={mix} label="Saved analyses by severity" size={96} thickness={12}>
          <p className="text-[20px] font-semibold text-fg-1 tabular-nums leading-none">{entries.length}</p>
        </SeverityDonut>
        <div className="min-w-0">
          <h2 className="wb-label mb-2">By severity</h2>
          <div className="[&_ul]:flex-col [&_ul]:gap-y-1"><SeverityLegend mix={mix} /></div>
        </div>
      </section>
      <section className="wb-card p-4">
        <h2 className="wb-label mb-3">Last 7 days</h2>
        <SeverityColumns columns={columns} label="Saved analyses per day" height={72} />
      </section>
      <section className="wb-card p-4">
        <h2 className="wb-label mb-3">Indicator types</h2>
        <ul className="space-y-1.5">
          {types.slice(0, 5).map(([type, n]) => (
            <li key={type} className="grid grid-cols-[56px_1fr_20px] items-center gap-2 text-[11px]">
              <span className="text-fg-2">{IOC_TYPE_LABEL[type] ?? type}</span>
              <span className="h-2 rounded-full bg-raised overflow-hidden">
                <span className={`block h-full rounded-full ${iocTypeDot(type)}`} style={{ width: `${(n / maxType) * 100}%` }} />
              </span>
              <span className="text-right tabular-nums text-fg-1 font-medium">{n}</span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

export function SearchHistoryPanel({ entries, onLoad, onRemove, onClear }: SearchHistoryPanelProps) {
  return (
    <div className="space-y-4">
      {entries.length > 0 && <HistorySummary entries={entries} />}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs text-fg-4 mt-0.5">
            {entries.length} saved {entries.length === 1 ? 'analysis' : 'analyses'}. The latest 10 are kept automatically; opening one doesn’t query providers again.
          </p>
        </div>
        {entries.length > 0 && (
          <button
            onClick={onClear}
            className="text-xs font-medium text-fg-4 hover:text-danger-fg transition-colors px-3 py-1.5 rounded-lg border border-line hover:border-danger-line bg-surface"
          >
            Clear all
          </button>
        )}
      </div>

      {/* Empty state */}
      {entries.length === 0 && (
        <div className="wb-card p-12 flex flex-col items-center gap-3 text-center">
          <ClockIcon />
          <div>
            <p className="text-sm font-medium text-fg-2">No searches saved yet</p>
            <p className="text-xs text-fg-4 mt-1 max-w-[300px] leading-relaxed">
              Run an analysis from the Single IOC tab — results are saved here automatically.
            </p>
          </div>
        </div>
      )}

      {/* Entry list */}
      {entries.length > 0 && (
        <div className="space-y-2">
          {entries.map(entry => {
            const sev = entry.result.overall.severity ?? 'unknown';
            const sevStyle = SEV_STYLES[sev] ?? SEV_STYLES['unknown']!;
            const iocType = entry.ioc.type;
            const okCount = entry.result.results.filter(r => r.status === 'ok' || r.status === 'cached').length;
            const totalCount = entry.result.results.length;

            return (
              <div
                key={entry.id}
                className="wb-card overflow-hidden"
              >
                <div className={`p-4 border-l-[3px] ${sevStyle.rule}`}>
                  <div className="flex items-start gap-3">
                    {/* Left: IOC info */}
                    <div className="flex-1 min-w-0 space-y-2">
                      {/* IOC value */}
                      <div className="flex items-center gap-2 flex-wrap">
                        <IocTypeChip type={iocType} size="sm" />
                        <code className="text-[13px] font-mono text-fg-1 font-medium truncate max-w-[320px]">
                          {entry.ioc.normalised}
                        </code>
                      </div>

                      {/* Verdict + meta row */}
                      <div className="flex items-center gap-2 flex-wrap">
                        {/* Severity badge */}
                        <span className={`inline-flex items-center gap-1.5 h-5 px-2 rounded text-[10px] font-semibold border ${sevStyle.bg} ${sevStyle.border} ${sevStyle.text}`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${sevStyle.dot}`} />
                          {sev.charAt(0).toUpperCase() + sev.slice(1)}
                        </span>

                        {/* Provider count */}
                        <span className="text-[11px] text-fg-4">
                          {okCount}/{totalCount} providers
                        </span>

                        {/* Workflow */}
                        {entry.workflowId && (
                          <span className="text-[11px] text-fg-3 bg-raised px-1.5 py-0.5 rounded font-medium">
                            {entry.workflowId}
                          </span>
                        )}

                        {/* Timestamp */}
                        <span className="text-[11px] text-fg-4 ml-auto">
                          {relativeTime(entry.savedAt)}
                        </span>
                      </div>

                      {/* Narrative preview */}
                      {entry.result.narrative && (
                        <p className="text-[11px] text-fg-3 leading-relaxed line-clamp-2">
                          {entry.result.narrative.replace(/\*+/g, '').replace(/^(VERDICT|KEY FINDINGS|RECOMMENDED ACTIONS|ANALYST NOTES):/gim, '').trim().slice(0, 180)}
                        </p>
                      )}
                    </div>

                    {/* Right: actions */}
                    <div className="flex flex-col gap-1.5 shrink-0">
                      <button
                        onClick={() => onLoad(entry)}
                        className="text-xs font-semibold px-3 py-1.5 rounded-lg bg-accent text-white hover:bg-accent-strong transition-colors whitespace-nowrap"
                      >
                        Load
                      </button>
                      <button
                        onClick={() => onRemove(entry.id)}
                        className="text-xs font-medium px-3 py-1.5 rounded-lg border border-line bg-surface text-fg-4 hover:text-danger-fg hover:border-danger-line transition-colors"
                      >
                        Remove
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
