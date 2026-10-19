import { useMemo } from 'react';
import type { ReactNode } from 'react';
import type { HistoryEntry } from '../lib/searchHistory';
import type { CaseRecord } from '../types/case';
import type { Tab } from './AppShell';
import { countSeverities } from '../lib/severityMix';
import { lastSevenDays } from '../lib/activity';
import { SeverityColumns, SeverityDonut, SeverityLegend, BUCKET_BG } from './charts';
import { IocTypeChip } from './IocTypeChip';

/**
 * Shown on the Investigate page before an indicator is entered: what is open,
 * what was looked at recently and how bad it was. Everything here is read from
 * this browser's history and cases.
 */

interface Props {
  history: HistoryEntry[];
  cases: CaseRecord[];
  configuredProviders: number | null;
  onLoadHistory: (entry: HistoryEntry) => void;
  onNavigate: (tab: Tab) => void;
}

function Stat({ tone, icon, value, label, sub, onClick }: {
  tone: string; icon: ReactNode; value: ReactNode; label: string; sub?: string; onClick?: () => void;
}) {
  return (
    <button onClick={onClick} className="wb-card text-left p-4 flex items-center gap-3.5 hover:border-line-strong transition-colors">
      <span className={`w-10 h-10 rounded-full grid place-items-center shrink-0 ${tone}`} aria-hidden>{icon}</span>
      <span className="min-w-0">
        <span className="block text-[22px] leading-none font-semibold text-fg-1 tabular-nums">{value}</span>
        <span className="block mt-1 text-xs text-fg-2">{label}</span>
        {sub && <span className="block text-[11px] text-fg-4 truncate">{sub}</span>}
      </span>
    </button>
  );
}

const ico = (d: ReactNode) => (
  <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">{d}</svg>
);

const SEV_DOT: Record<string, string> = {
  critical: BUCKET_BG.critical, high: BUCKET_BG.high, medium: BUCKET_BG.medium, low: BUCKET_BG.low, benign: BUCKET_BG.benign, unknown: BUCKET_BG.info,
};

function relative(iso: string): string {
  const m = Math.floor((Date.now() - new Date(iso).getTime()) / 60_000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export function InvestigateOverview({ history, cases, configuredProviders, onLoadHistory, onNavigate }: Props) {
  const columns = useMemo(() => lastSevenDays(history), [history]);
  const mix = useMemo(() => countSeverities(history.map(e => e.result.overall.severity)), [history]);
  const open = cases.filter(c => c.status === 'open').length;
  const severe = mix.critical + mix.high;
  const weekTotal = columns.reduce((n, c) => n + (Object.values(c.mix) as number[]).reduce((a, b) => a + b, 0), 0);

  return (
    <div className="space-y-4">
      <div className="grid gap-3 grid-cols-2 xl:grid-cols-4">
        <Stat
          tone="bg-c1-bg text-c1-fg" onClick={() => onNavigate('cases')}
          icon={ico(<path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z" />)}
          value={open} label="Open cases" sub={`${cases.length - open} closed`}
        />
        <Stat
          tone="bg-c2-bg text-c2-fg" onClick={() => onNavigate('history')}
          icon={ico(<><path d="M3 12a9 9 0 103-6.7L3 8" /><path d="M3 3v5h5M12 7v5l3 2" /></>)}
          value={history.length} label="Saved analyses" sub={`${weekTotal} in the last 7 days`}
        />
        <Stat
          tone="bg-c4-bg text-c4-fg" onClick={() => onNavigate('history')}
          icon={ico(<><path d="M12 3l9 16H3z" /><path d="M12 10v4M12 17h.01" /></>)}
          value={severe} label="High or critical" sub="among saved analyses"
        />
        <Stat
          tone="bg-c5-bg text-c5-fg" onClick={() => onNavigate('apikeys')}
          icon={ico(<><circle cx="8" cy="15" r="4" /><path d="M10.8 12.2L20 3M16 7l3 3M14 9l2 2" /></>)}
          value={configuredProviders ?? '–'} label="Provider keys set" sub={configuredProviders === null ? 'backend offline' : 'keyless sources always run'}
        />
      </div>

      {history.length > 0 && (
        <div className="grid gap-3 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)_minmax(0,1.2fr)]">
          <section className="wb-card p-4">
            <div className="flex items-baseline justify-between mb-3">
              <h2 className="wb-label">Activity</h2>
              <span className="text-[11px] text-fg-4">Saved analyses, last 7 days</span>
            </div>
            <SeverityColumns columns={columns} label="Saved analyses per day by severity" height={112} />
          </section>

          <section className="wb-card p-4">
            <h2 className="wb-label mb-3">Severity mix</h2>
            <div className="flex items-center gap-4">
              <SeverityDonut mix={mix} label="Saved analyses by severity" size={108} thickness={13}>
                <div className="leading-none">
                  <p className="text-[22px] font-semibold text-fg-1 tabular-nums">{history.length}</p>
                  <p className="mt-1 text-[10px] uppercase tracking-[.06em] text-fg-4">analyses</p>
                </div>
              </SeverityDonut>
              <div className="min-w-0 [&_ul]:flex-col [&_ul]:gap-y-1.5">
                <SeverityLegend mix={mix} />
              </div>
            </div>
          </section>

          <section className="wb-card p-4 min-w-0">
            <div className="flex items-baseline justify-between mb-2">
              <h2 className="wb-label">Recent indicators</h2>
              <button onClick={() => onNavigate('history')} className="text-[11px] text-accent-fg hover:underline">History</button>
            </div>
            <ul className="-mx-1.5">
              {history.slice(0, 5).map(e => (
                <li key={e.id}>
                  <button
                    onClick={() => onLoadHistory(e)}
                    className="w-full flex items-center gap-2 px-1.5 py-1.5 rounded-md hover:bg-inset text-left"
                    title="Open saved result"
                  >
                    <span className={`w-2 h-2 rounded-full shrink-0 ${SEV_DOT[e.result.overall.severity] ?? BUCKET_BG.info}`} aria-label={e.result.overall.severity} />
                    <IocTypeChip type={e.ioc.type} size="sm" />
                    <code className="flex-1 min-w-0 truncate text-xs font-mono text-fg-1">{e.ioc.normalised}</code>
                    <span className="text-[11px] text-fg-4 shrink-0">{relative(e.savedAt)}</span>
                  </button>
                </li>
              ))}
            </ul>
          </section>
        </div>
      )}
    </div>
  );
}
