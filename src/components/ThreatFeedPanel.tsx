import { useState, useCallback, useEffect, useMemo } from 'react';
import { StackedColumns, SeriesLegend, RankBars } from './charts';
import type { Series } from './charts';
import { IocTypeChip } from './IocTypeChip';
import { dailyCounts, topCounts } from '../lib/activity';

const API_BASE = '/api';

// ── Pulsedive types ────────────────────────────────────────────────────────

interface Indicator {
  iid?: number;
  indicator?: string;
  type?: string;
  risk?: string;
  stamp_added?: string;
  stamp_updated?: string;
  stamp_seen?: string;
  summary?: {
    threats?: Array<{ name?: string }>;
    feeds?: Array<{ name?: string }>;
    properties?: { geo?: { country?: string } };
  };
}

interface FeedSection {
  label: string;
  query: string;
  indicators: Indicator[];
  error?: string;
}

interface ThreatFeedResponse {
  sections: FeedSection[];
  totalCount: number;
  fetchedAt: string;
  source: string;
}

// ── Briefing types ─────────────────────────────────────────────────────────

interface ThreatEvent {
  id: string;
  type: 'cve' | 'ransomware' | 'malware' | 'advisory';
  title: string;
  summary: string;
  severity: 'critical' | 'high' | 'medium' | 'informational';
  source: string;
  sourceUrl: string;
  publishedAt: string;
  tags: string[];
  cve?: string;
  ransomwareGroup?: string;
  affectedProducts?: string[];
  victim?: string;
  country?: string;
  sector?: string;
}

interface ThreatBriefingResponse {
  events: ThreatEvent[];
  fetchedAt: string;
  errors: Record<string, string>;
}

// ── Shared helpers ─────────────────────────────────────────────────────────

const RISK_BADGE: Record<string, string> = {
  critical: 'bg-danger-bg text-danger-fg border-danger-line',
  high:     'bg-high-bg text-high-fg border-high-line',
  medium:   'bg-warn-bg text-warn-fg border-warn-line',
  low:      'bg-accent-bg text-accent-fg border-accent-line',
  none:     'bg-ok-bg text-ok-fg border-ok-line',
  unknown:  'bg-raised text-fg-2 border-line',
};

const RISK_DOT: Record<string, string> = {
  critical: 'bg-danger',
  high:     'bg-high',
  medium:   'bg-warn',
  low:      'bg-accent',
  none:     'bg-ok',
  unknown:  'bg-fg-4',
};

function RiskBadge({ risk }: { risk?: string }) {
  const r = (risk ?? 'unknown').toLowerCase();
  const cls = RISK_BADGE[r] ?? RISK_BADGE.unknown;
  const dot = RISK_DOT[r] ?? RISK_DOT.unknown;
  return (
    <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] border font-semibold ${cls}`}>
      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dot}`} />
      {r.toUpperCase()}
    </span>
  );
}

function formatDate(ts?: string): string {
  if (!ts) return '—';
  try {
    const d = new Date(ts.includes('T') ? ts : ts.replace(' ', 'T') + 'Z');
    return d.toLocaleDateString(undefined, { day: '2-digit', month: 'short' });
  } catch { return ts; }
}

// ── Briefing event card ────────────────────────────────────────────────────

// Event types use the categorical ramp (CVE teal matches CVE indicators); severity stays on the badge
const TYPE_ICON: Record<ThreatEvent['type'], string> = {
  cve: 'bg-c5-bg text-c5-fg',
  ransomware: 'bg-c3-bg text-c3-fg',
  malware: 'bg-c4-bg text-c4-fg',
  advisory: 'bg-c1-bg text-c1-fg',
};

const TYPE_RULE: Record<ThreatEvent['type'], string> = {
  cve: 'bg-c5', ransomware: 'bg-c3', malware: 'bg-c4', advisory: 'bg-c1',
};

const EVENT_SERIES: Series[] = [
  { key: 'cve', label: 'CISA KEV', bg: 'bg-c5' },
  { key: 'ransomware', label: 'Ransomware', bg: 'bg-c3' },
];

function BriefingOverview({ events }: { events: ThreatEvent[] }) {
  const columns = useMemo(() => dailyCounts(events, e => e.publishedAt, e => e.type, 30), [events]);
  const counts = useMemo(() => Object.fromEntries(EVENT_SERIES.map(s => [s.key, events.filter(e => e.type === s.key).length])), [events]);
  const groups = useMemo(() => topCounts(events.filter(e => e.type === 'ransomware').map(e => e.ransomwareGroup)), [events]);
  const vendors = useMemo(() => topCounts(events.filter(e => e.type === 'cve').map(e => e.affectedProducts?.[0])), [events]);
  const sectors = useMemo(() => topCounts(events.filter(e => e.type === 'ransomware').map(e => e.sector), ['not found', 'other', 'unknown']), [events]);

  return (
    <div className="grid gap-3 lg:grid-cols-2 xl:grid-cols-[minmax(0,1.6fr)_repeat(3,minmax(0,1fr))]">
      <section className="wb-card p-4 lg:col-span-2 xl:col-span-1">
        <div className="flex flex-wrap items-baseline justify-between gap-2 mb-3">
          <h2 className="wb-label">Last 30 days</h2>
          <SeriesLegend series={EVENT_SERIES} counts={counts} />
        </div>
        <StackedColumns columns={columns} series={EVENT_SERIES} label="Briefing events per day" height={96} labelEvery={7} />
      </section>
      <section className="wb-card p-4">
        <h2 className="wb-label mb-3">Most active groups</h2>
        <RankBars items={groups} bg="bg-c3" label="Ransomware posts by group" />
      </section>
      <section className="wb-card p-4">
        <h2 className="wb-label mb-3">Exploited vendors</h2>
        <RankBars items={vendors} bg="bg-c5" label="KEV additions by vendor" />
      </section>
      <section className="wb-card p-4">
        <h2 className="wb-label mb-3">Victim sectors</h2>
        <RankBars items={sectors} bg="bg-c2" label="Ransomware victims by sector" />
      </section>
    </div>
  );
}

const TYPE_LABEL: Record<ThreatEvent['type'], string> = {
  cve: 'CVE',
  ransomware: 'Ransomware',
  malware: 'Malware',
  advisory: 'Advisory',
};

function EventCard({ event }: { event: ThreatEvent }) {
  const [expanded, setExpanded] = useState(false);
  const iconCls = TYPE_ICON[event.type] ?? 'bg-raised text-fg-3';

  return (
    <div className="relative wb-card overflow-hidden">
      <span className={`absolute left-0 top-0 bottom-0 w-[3px] ${TYPE_RULE[event.type] ?? 'bg-line-strong'}`} aria-hidden />
      <button
        onClick={() => setExpanded(v => !v)}
        aria-expanded={expanded}
        className="w-full flex items-start gap-3 pl-4 pr-3.5 py-3 text-left hover:bg-inset transition-colors"
      >
        <span className={`mt-0.5 h-6 px-1.5 rounded-md flex items-center justify-center text-[10px] font-semibold shrink-0 ${iconCls}`}>
          {event.type === 'cve' ? 'KEV' : TYPE_LABEL[event.type]}
        </span>

        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-2">
            <p className="text-[13px] font-semibold text-fg-1 leading-snug">{event.title}</p>
            <div className="flex items-center gap-1.5 shrink-0">
              <RiskBadge risk={event.severity} />
              <span className="text-[11px] text-fg-4 whitespace-nowrap">{formatDate(event.publishedAt)}</span>
            </div>
          </div>
          <div className="flex items-center gap-2 mt-1">
            <span className="text-[11px] text-fg-3">{event.source}</span>
            {event.tags.slice(0, 3).map(t => (
              <span key={t} className="text-[10px] bg-raised text-fg-2 px-1.5 py-0 rounded border border-line">{t}</span>
            ))}
          </div>
        </div>

        <svg className={`w-3.5 h-3.5 text-fg-4 mt-1 shrink-0 transition-transform ${expanded ? 'rotate-180' : ''}`}
          fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {expanded && (
        <div className="px-3.5 pb-3.5 border-t border-line-soft pt-3 space-y-2">
          <p className="text-xs text-fg-2 leading-relaxed">{event.summary}</p>
          {event.affectedProducts && event.affectedProducts.length > 0 && (
            <p className="text-xs text-fg-3">
              <span className="font-medium">Affected:</span> {event.affectedProducts.join(', ')}
            </p>
          )}
          {event.country && (
            <p className="text-xs text-fg-3">
              <span className="font-medium">Country:</span> {event.country}
              {event.sector ? ` · ${event.sector}` : ''}
            </p>
          )}
          <a href={event.sourceUrl} target="_blank" rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-accent-fg hover:text-accent-fg font-medium">
            View source ↗
          </a>
        </div>
      )}
    </div>
  );
}

// ── Pulsedive section card ─────────────────────────────────────────────────

const PULSEDIVE_TYPE: Record<string, string> = { ip: 'ipv4', ipv6: 'ipv6', domain: 'domain', url: 'url' };

function TypeBadge({ type }: { type?: string }) {
  return <IocTypeChip type={PULSEDIVE_TYPE[type ?? ''] ?? type ?? 'unknown'} size="sm" />;
}

function IndicatorRow({ item }: { item: Indicator }) {
  const threats = item.summary?.threats?.map(t => t.name).filter(Boolean) ?? [];
  const feeds = item.summary?.feeds?.map(f => f.name).filter(Boolean) ?? [];
  const country = item.summary?.properties?.geo?.country;

  return (
    <tr className="hover:bg-raised/30 transition-colors">
      <td className="px-3 py-2 font-mono text-fg-1 max-w-xs">
        <div className="flex items-center gap-2 min-w-0">
          <TypeBadge type={item.type} />
          {item.iid ? (
            <a href={`https://pulsedive.com/indicator/?iid=${item.iid}`} target="_blank" rel="noopener noreferrer"
              className="truncate hover:text-accent-fg transition-colors text-sm" title={item.indicator}>
              {item.indicator}
            </a>
          ) : (
            <span className="truncate text-sm" title={item.indicator}>{item.indicator}</span>
          )}
          {country && <span className="text-fg-4 text-xs shrink-0">{country}</span>}
        </div>
        {(threats.length > 0 || feeds.length > 0) && (
          <div className="flex flex-wrap gap-1 mt-1">
            {threats.slice(0, 2).map(t => (
              <span key={t} className="text-xs bg-raised text-fg-3 px-1 rounded">{t}</span>
            ))}
            {feeds.slice(0, 1).map(f => (
              <span key={f} className="text-xs bg-accent-bg text-accent-fg px-1 rounded border border-accent-line">{f}</span>
            ))}
          </div>
        )}
      </td>
      <td className="px-3 py-2 shrink-0"><RiskBadge risk={item.risk} /></td>
      <td className="px-3 py-2 text-xs text-fg-4 whitespace-nowrap">
        {formatDate(item.stamp_seen ?? item.stamp_updated)}
      </td>
    </tr>
  );
}

const SECTION_COLOR: Record<string, string> = {
  'Critical Threats':          'var(--color-danger)',
  'High Risk Infrastructure':  'var(--color-high)',
  'High Risk Domains & URLs':  'var(--color-warn)',
};

function PulsediveSectionCard({ section }: { section: FeedSection }) {
  const dotColor = SECTION_COLOR[section.label] ?? 'var(--color-fg-3)';
  return (
    <div className="wb-card overflow-hidden flex flex-col">
      <div className="flex items-center justify-between px-4 py-3 border-b border-line">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full shrink-0" style={{ background: dotColor }} />
          <h3 className="text-[13px] font-semibold text-fg-1">{section.label}</h3>
        </div>
        <div className="flex items-center gap-2">
          <code className="text-xs text-fg-4 font-mono">{section.query}</code>
          {section.indicators.length > 0 && (
            <span className="text-xs bg-raised text-fg-2 px-1.5 py-0.5 rounded">
              {section.indicators.length}
            </span>
          )}
        </div>
      </div>
      {section.indicators.length === 0 ? (
        <div className="flex-1 flex items-center justify-center py-8 text-sm text-fg-4">
          {section.error ? `Error: ${section.error}` : 'No indicators found.'}
        </div>
      ) : (
        <div className="overflow-x-auto flex-1">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-inset">
                <th className="text-left px-3 py-2 text-fg-3 font-medium">Indicator</th>
                <th className="text-left px-3 py-2 text-fg-3 font-medium">Risk</th>
                <th className="text-left px-3 py-2 text-fg-3 font-medium">Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line-soft">
              {section.indicators.map((item, i) => (
                <IndicatorRow key={item.iid ?? i} item={item} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── Main panel ────────────────────────────────────────────────────────────

type ActiveView = 'briefing' | 'pulsedive';

export function ThreatFeedPanel() {
  const [activeView, setActiveView] = useState<ActiveView>('briefing');

  // Briefing state
  const [briefing, setBriefing] = useState<ThreatBriefingResponse | null>(null);
  const [briefingLoading, setBriefingLoading] = useState(false);
  const [briefingError, setBriefingError] = useState<string | null>(null);
  const [briefingRefreshed, setBriefingRefreshed] = useState<Date | null>(null);
  const [typeFilter, setTypeFilter] = useState<ThreatEvent['type'] | 'all'>('all');

  // Pulsedive state
  const [pulsediveData, setPulsediveData] = useState<ThreatFeedResponse | null>(null);
  const [pulsediveLoading, setPulsediveLoading] = useState(false);
  const [pulsediveError, setPulsediveError] = useState<string | null>(null);
  const [pulsediveRefreshed, setPulsediveRefreshed] = useState<Date | null>(null);

  const fetchBriefing = useCallback(async () => {
    setBriefingLoading(true);
    setBriefingError(null);
    try {
      const res = await fetch(`${API_BASE}/threat-briefing`);
      if (!res.ok) {
        const json = await res.json().catch(() => null) as { error?: string } | null;
        setBriefingError(json?.error ?? `HTTP ${res.status}`);
        return;
      }
      setBriefing(await res.json() as ThreatBriefingResponse);
      setBriefingRefreshed(new Date());
    } catch (e) {
      setBriefingError(e instanceof TypeError ? 'Backend unreachable — start it with npm run backend:dev.' : e instanceof Error ? e.message : 'Network error — is the backend running?');
    } finally {
      setBriefingLoading(false);
    }
  }, []);

  const fetchPulsedive = useCallback(async () => {
    setPulsediveLoading(true);
    setPulsediveError(null);
    try {
      const res = await fetch(`${API_BASE}/threat-feed`);
      if (!res.ok) {
        const json = await res.json().catch(() => null) as { error?: string } | null;
        setPulsediveError(json?.error ?? `HTTP ${res.status}`);
        return;
      }
      setPulsediveData(await res.json() as ThreatFeedResponse);
      setPulsediveRefreshed(new Date());
    } catch (e) {
      setPulsediveError(e instanceof TypeError ? 'Backend unreachable — start it with npm run backend:dev.' : e instanceof Error ? e.message : 'Network error — is the backend running?');
    } finally {
      setPulsediveLoading(false);
    }
  }, []);

  // Auto-fetch briefing on mount
  useEffect(() => { void fetchBriefing(); }, [fetchBriefing]);

  const filteredEvents = briefing?.events.filter(e =>
    typeFilter === 'all' || e.type === typeFilter
  ) ?? [];

  const kevCount = briefing?.events.filter(e => e.type === 'cve').length ?? 0;
  const ransomCount = briefing?.events.filter(e => e.type === 'ransomware').length ?? 0;
  const loading = activeView === 'briefing' ? briefingLoading : pulsediveLoading;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="wb-card p-4">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <p className="text-xs text-fg-3">
            Sources: <span className="text-fg-2">CISA KEV</span> · <span className="text-fg-2">Ransomware.live</span> · <span className="text-fg-2">Pulsedive</span>
          </p>

          <div className="flex items-center gap-2">
            {/* View toggle */}
            <div className="flex rounded-lg border border-line overflow-hidden text-xs">
              {(['briefing', 'pulsedive'] as const).map(v => (
                <button key={v} onClick={() => {
                  setActiveView(v);
                  if (v === 'pulsedive' && !pulsediveData && !pulsediveLoading) void fetchPulsedive();
                }}
                  aria-pressed={activeView === v}
                  className={`px-3 py-1.5 font-medium transition-colors ${
                    activeView === v
                      ? 'bg-selected text-selected-fg'
                      : 'bg-surface text-fg-3 hover:bg-raised'
                  }`}>
                  {v === 'briefing' ? 'Threat Briefing' : 'Pulsedive'}
                </button>
              ))}
            </div>

            <button
              onClick={() => activeView === 'briefing' ? void fetchBriefing() : void fetchPulsedive()}
              disabled={loading}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-surface hover:bg-raised border border-line rounded-lg transition-colors disabled:opacity-50"
            >
              <svg className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              {loading ? 'Fetching…' : 'Refresh'}
            </button>
          </div>
        </div>

        {/* Briefing stats row */}
        {activeView === 'briefing' && briefing && !briefingLoading && (
          <div className="mt-3 pt-3 border-t border-line flex flex-wrap items-center gap-4 text-xs">
            <span className="text-fg-3">
              <span className="font-semibold text-fg-1">{briefing.events.length}</span> events
            </span>
            {kevCount > 0 && (
              <span className="text-c5-fg font-semibold">{kevCount} CISA KEV</span>
            )}
            {ransomCount > 0 && (
              <span className="text-c3-fg font-semibold">{ransomCount} ransomware</span>
            )}
            {briefingRefreshed && (
              <span className="text-fg-4 ml-auto">Updated {briefingRefreshed.toLocaleTimeString()}</span>
            )}
            {Object.entries(briefing.errors).map(([src, err]) => (
              <span key={src} className="text-warn-fg">{src}: {err}</span>
            ))}
          </div>
        )}

        {/* Pulsedive stats row */}
        {activeView === 'pulsedive' && pulsediveData && !pulsediveLoading && (
          <div className="mt-3 pt-3 border-t border-line flex flex-wrap gap-4 text-xs">
            <span className="text-fg-3">
              <span className="font-semibold text-fg-1">{pulsediveData.totalCount}</span> indicators
            </span>
            {pulsediveRefreshed && (
              <span className="text-fg-4 ml-auto">Updated {pulsediveRefreshed.toLocaleTimeString()}</span>
            )}
          </div>
        )}
      </div>

      {/* Error states */}
      {activeView === 'briefing' && briefingError && (
        <div className="wb-card bg-warn-bg border-warn-line p-4 text-sm text-warn-fg">{briefingError}</div>
      )}
      {activeView === 'pulsedive' && pulsediveError && (
        <div className="wb-card bg-warn-bg border-warn-line p-4 text-sm text-warn-fg">{pulsediveError}</div>
      )}

      {/* Loading */}
      {loading && (
        <div className="flex items-center gap-2 text-sm text-fg-3 px-1">
          <div className="w-4 h-4 rounded-full border-2 border-line border-t-accent animate-spin" />
          Fetching threat data…
        </div>
      )}

      {/* ── Briefing view ───────────────────────────────────────────────── */}
      {activeView === 'briefing' && briefing && !briefingLoading && (
        <div className="space-y-3">
          {briefing.events.length > 0 && <BriefingOverview events={briefing.events} />}

          {/* Type filter */}
          <div className="flex gap-1.5 flex-wrap">
            {(['all', 'cve', 'ransomware'] as const).map(t => (
              <button key={t} onClick={() => setTypeFilter(t)}
                aria-pressed={typeFilter === t}
                className={`flex items-center gap-1.5 h-7 px-2.5 text-xs rounded-md border font-medium transition-colors ${
                  typeFilter === t
                    ? 'bg-selected text-selected-fg border-selected'
                    : 'bg-surface text-fg-2 border-line hover:border-line-strong'
                }`}>
                {t !== 'all' && <span className={`w-2 h-2 rounded-full ${TYPE_RULE[t]}`} aria-hidden />}
                {t === 'all' ? `All (${briefing.events.length})` : t === 'cve' ? `CISA KEV (${kevCount})` : `Ransomware (${ransomCount})`}
              </button>
            ))}
          </div>

          {filteredEvents.length === 0 ? (
            <p className="text-sm text-fg-4 px-1">No events match the selected filter.</p>
          ) : (
            <div className="space-y-2">
              {filteredEvents.map(event => (
                <EventCard key={event.id} event={event} />
              ))}
            </div>
          )}

          <p className="text-xs text-fg-4 text-center pt-1">
            Sources:{' '}
            <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer" className="hover:text-fg-3 underline">CISA KEV</a>
            {' · '}
            <a href="https://www.ransomware.live" target="_blank" rel="noopener noreferrer" className="hover:text-fg-3 underline">Ransomware.live</a>
          </p>
        </div>
      )}

      {/* ── Pulsedive view ──────────────────────────────────────────────── */}
      {activeView === 'pulsedive' && pulsediveData && !pulsediveLoading && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
            {pulsediveData.sections.map(section => (
              <PulsediveSectionCard key={section.label} section={section} />
            ))}
          </div>
          <p className="text-xs text-fg-4 text-center">
            Threat data from{' '}
            <a href="https://pulsedive.com" target="_blank" rel="noopener noreferrer" className="hover:text-fg-3 underline">pulsedive.com</a>
          </p>
        </div>
      )}

      {/* Pulsedive empty state */}
      {activeView === 'pulsedive' && !pulsediveData && !pulsediveLoading && !pulsediveError && (
        <p className="text-sm text-fg-4 px-1">Click Refresh to load Pulsedive indicators.</p>
      )}
    </div>
  );
}
