import { useState, useCallback, useEffect } from 'react';

const API_BASE = 'http://localhost:8787/api';

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
  critical: 'bg-[#fef3f2] text-[#b42318] border-[#fecdca]',
  high:     'bg-[#fff4ed] text-[#9c3a10] border-[#fddcbc]',
  medium:   'bg-[#fffaeb] text-[#b54708] border-[#fedf89]',
  low:      'bg-[#eff8ff] text-[#175cd3] border-[#b2ddff]',
  none:     'bg-[#ecfdf3] text-[#067647] border-[#abefc6]',
  unknown:  'bg-[#f2f4f7] text-[#344054] border-[#e4e7ec]',
};

const RISK_DOT: Record<string, string> = {
  critical: 'bg-[#d92d20]',
  high:     'bg-[#ef6820]',
  medium:   'bg-[#dc6803]',
  low:      'bg-[#1570ef]',
  none:     'bg-[#079455]',
  unknown:  'bg-[#98a2b3]',
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

const TYPE_ICON: Record<ThreatEvent['type'], string> = {
  cve: 'bg-[#fef3f2] text-[#d92d20]',
  ransomware: 'bg-[#fff4ed] text-[#ef6820]',
  malware: 'bg-[#f4f3ff] text-[#5925dc]',
  advisory: 'bg-[#eff8ff] text-[#1570ef]',
};

const TYPE_LABEL: Record<ThreatEvent['type'], string> = {
  cve: 'CVE',
  ransomware: 'Ransomware',
  malware: 'Malware',
  advisory: 'Advisory',
};

function EventCard({ event }: { event: ThreatEvent }) {
  const [expanded, setExpanded] = useState(false);
  const iconCls = TYPE_ICON[event.type] ?? 'bg-[#f2f4f7] text-[#667085]';

  return (
    <div className="bg-white border border-[#e4e7ec] rounded-lg overflow-hidden">
      <button
        onClick={() => setExpanded(v => !v)}
        className="w-full flex items-start gap-3 px-3.5 py-3 text-left hover:bg-[#f9fafb] transition-colors"
      >
        {/* Type dot */}
        <span className={`mt-0.5 w-6 h-6 rounded flex items-center justify-center text-[10px] font-bold shrink-0 ${iconCls}`}>
          {TYPE_LABEL[event.type][0]}
        </span>

        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-2">
            <p className="text-[13px] font-semibold text-[#101828] leading-snug">{event.title}</p>
            <div className="flex items-center gap-1.5 shrink-0">
              <RiskBadge risk={event.severity} />
              <span className="text-[11px] text-[#98a2b3] whitespace-nowrap">{formatDate(event.publishedAt)}</span>
            </div>
          </div>
          <div className="flex items-center gap-2 mt-1">
            <span className="text-[11px] text-[#667085]">{event.source}</span>
            {event.tags.slice(0, 3).map(t => (
              <span key={t} className="text-[10px] bg-[#f2f4f7] text-[#475467] px-1.5 py-0 rounded border border-[#e4e7ec]">{t}</span>
            ))}
          </div>
        </div>

        <svg className={`w-3.5 h-3.5 text-[#98a2b3] mt-1 shrink-0 transition-transform ${expanded ? 'rotate-180' : ''}`}
          fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {expanded && (
        <div className="px-3.5 pb-3.5 border-t border-[#f2f4f7] pt-3 space-y-2">
          <p className="text-xs text-[#475467] leading-relaxed">{event.summary}</p>
          {event.affectedProducts && event.affectedProducts.length > 0 && (
            <p className="text-xs text-[#667085]">
              <span className="font-medium">Affected:</span> {event.affectedProducts.join(', ')}
            </p>
          )}
          {event.country && (
            <p className="text-xs text-[#667085]">
              <span className="font-medium">Country:</span> {event.country}
              {event.sector ? ` · ${event.sector}` : ''}
            </p>
          )}
          <a href={event.sourceUrl} target="_blank" rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-[#1570ef] hover:text-[#175cd3] font-medium">
            View source ↗
          </a>
        </div>
      )}
    </div>
  );
}

// ── Pulsedive section card ─────────────────────────────────────────────────

function TypeBadge({ type }: { type?: string }) {
  return (
    <span className="text-xs bg-[#f2f4f7] text-[#667085] border border-[#d0d5dd] px-1.5 py-0.5 rounded font-mono">
      {type ?? '?'}
    </span>
  );
}

function IndicatorRow({ item }: { item: Indicator }) {
  const threats = item.summary?.threats?.map(t => t.name).filter(Boolean) ?? [];
  const feeds = item.summary?.feeds?.map(f => f.name).filter(Boolean) ?? [];
  const country = item.summary?.properties?.geo?.country;

  return (
    <tr className="hover:bg-[#f2f4f7]/30 transition-colors">
      <td className="px-3 py-2 font-mono text-[#101828] max-w-xs">
        <div className="flex items-center gap-2 min-w-0">
          <TypeBadge type={item.type} />
          {item.iid ? (
            <a href={`https://pulsedive.com/indicator/?iid=${item.iid}`} target="_blank" rel="noopener noreferrer"
              className="truncate hover:text-[#1570ef] transition-colors text-sm" title={item.indicator}>
              {item.indicator}
            </a>
          ) : (
            <span className="truncate text-sm" title={item.indicator}>{item.indicator}</span>
          )}
          {country && <span className="text-[#98a2b3] text-xs shrink-0">{country}</span>}
        </div>
        {(threats.length > 0 || feeds.length > 0) && (
          <div className="flex flex-wrap gap-1 mt-1">
            {threats.slice(0, 2).map(t => (
              <span key={t} className="text-xs bg-[#f2f4f7] text-[#667085] px-1 rounded">{t}</span>
            ))}
            {feeds.slice(0, 1).map(f => (
              <span key={f} className="text-xs bg-[#eff8ff] text-[#175cd3] px-1 rounded border border-[#b2ddff]">{f}</span>
            ))}
          </div>
        )}
      </td>
      <td className="px-3 py-2 shrink-0"><RiskBadge risk={item.risk} /></td>
      <td className="px-3 py-2 text-xs text-[#98a2b3] whitespace-nowrap">
        {formatDate(item.stamp_seen ?? item.stamp_updated)}
      </td>
    </tr>
  );
}

const SECTION_COLOR: Record<string, string> = {
  'Critical Threats':          '#d92d20',
  'High Risk Infrastructure':  '#ef6820',
  'High Risk Domains & URLs':  '#dc6803',
};

function PulsediveSectionCard({ section }: { section: FeedSection }) {
  const dotColor = SECTION_COLOR[section.label] ?? '#667085';
  return (
    <div className="bg-white border border-[#e4e7ec] rounded-lg overflow-hidden flex flex-col">
      <div className="flex items-center justify-between px-4 py-3 border-b border-[#e4e7ec]">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full shrink-0" style={{ background: dotColor }} />
          <h3 className="text-[13px] font-semibold text-[#101828]">{section.label}</h3>
        </div>
        <div className="flex items-center gap-2">
          <code className="text-xs text-[#98a2b3] font-mono">{section.query}</code>
          {section.indicators.length > 0 && (
            <span className="text-xs bg-[#f2f4f7] text-[#344054] px-1.5 py-0.5 rounded">
              {section.indicators.length}
            </span>
          )}
        </div>
      </div>
      {section.indicators.length === 0 ? (
        <div className="flex-1 flex items-center justify-center py-8 text-sm text-[#98a2b3]">
          {section.error ? `Error: ${section.error}` : 'No indicators found.'}
        </div>
      ) : (
        <div className="overflow-x-auto flex-1">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-[#f9fafb]">
                <th className="text-left px-3 py-2 text-[#667085] font-medium">Indicator</th>
                <th className="text-left px-3 py-2 text-[#667085] font-medium">Risk</th>
                <th className="text-left px-3 py-2 text-[#667085] font-medium">Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#f2f4f7]">
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
      setBriefingError(e instanceof Error ? e.message : 'Network error — is the backend running?');
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
      setPulsediveError(e instanceof Error ? e.message : 'Network error — is the backend running?');
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
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-[#fef3f2] border border-[#fecdca] flex items-center justify-center shrink-0">
              <svg className="w-4 h-4 text-[#d92d20]" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            </div>
            <div>
              <h2 className="text-sm font-semibold text-[#101828]">Threat Feed</h2>
              <p className="text-xs text-[#667085]">Current threat landscape · CISA KEV, Ransomware.live, Pulsedive</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* View toggle */}
            <div className="flex rounded-lg border border-[#e4e7ec] overflow-hidden text-xs">
              {(['briefing', 'pulsedive'] as const).map(v => (
                <button key={v} onClick={() => {
                  setActiveView(v);
                  if (v === 'pulsedive' && !pulsediveData && !pulsediveLoading) void fetchPulsedive();
                }}
                  className={`px-3 py-1.5 font-medium transition-colors ${
                    activeView === v
                      ? 'bg-[#101828] text-white'
                      : 'bg-white text-[#667085] hover:bg-[#f2f4f7]'
                  }`}>
                  {v === 'briefing' ? 'Threat Briefing' : 'Pulsedive'}
                </button>
              ))}
            </div>

            <button
              onClick={() => activeView === 'briefing' ? void fetchBriefing() : void fetchPulsedive()}
              disabled={loading}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-white hover:bg-[#f2f4f7] border border-[#e4e7ec] rounded-lg transition-colors disabled:opacity-50"
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
          <div className="mt-3 pt-3 border-t border-[#e4e7ec] flex flex-wrap items-center gap-4 text-xs">
            <span className="text-[#667085]">
              <span className="font-semibold text-[#101828]">{briefing.events.length}</span> events
            </span>
            {kevCount > 0 && (
              <span className="text-[#b42318] font-semibold">{kevCount} CISA KEV</span>
            )}
            {ransomCount > 0 && (
              <span className="text-[#9c3a10] font-semibold">{ransomCount} ransomware</span>
            )}
            {briefingRefreshed && (
              <span className="text-[#98a2b3] ml-auto">Updated {briefingRefreshed.toLocaleTimeString()}</span>
            )}
            {Object.entries(briefing.errors).map(([src, err]) => (
              <span key={src} className="text-[#b54708]">{src}: {err}</span>
            ))}
          </div>
        )}

        {/* Pulsedive stats row */}
        {activeView === 'pulsedive' && pulsediveData && !pulsediveLoading && (
          <div className="mt-3 pt-3 border-t border-[#e4e7ec] flex flex-wrap gap-4 text-xs">
            <span className="text-[#667085]">
              <span className="font-semibold text-[#101828]">{pulsediveData.totalCount}</span> indicators
            </span>
            {pulsediveRefreshed && (
              <span className="text-[#98a2b3] ml-auto">Updated {pulsediveRefreshed.toLocaleTimeString()}</span>
            )}
          </div>
        )}
      </div>

      {/* Error states */}
      {activeView === 'briefing' && briefingError && (
        <div className="wb-card bg-[#fffaeb] border-[#fedf89] p-4 text-sm text-[#b54708]">{briefingError}</div>
      )}
      {activeView === 'pulsedive' && pulsediveError && (
        <div className="wb-card bg-[#fffaeb] border-[#fedf89] p-4 text-sm text-[#b54708]">{pulsediveError}</div>
      )}

      {/* Loading */}
      {loading && (
        <div className="flex items-center gap-2 text-sm text-[#667085] px-1">
          <div className="w-4 h-4 rounded-full border-2 border-[#e4e7ec] border-t-[#1570ef] animate-spin" />
          Fetching threat data…
        </div>
      )}

      {/* ── Briefing view ───────────────────────────────────────────────── */}
      {activeView === 'briefing' && briefing && !briefingLoading && (
        <div className="space-y-3">
          {/* Type filter */}
          <div className="flex gap-2 flex-wrap">
            {(['all', 'cve', 'ransomware'] as const).map(t => (
              <button key={t} onClick={() => setTypeFilter(t)}
                className={`px-3 py-1 text-xs rounded-full border font-medium transition-colors ${
                  typeFilter === t
                    ? 'bg-[#101828] text-white border-[#101828]'
                    : 'bg-white text-[#667085] border-[#e4e7ec] hover:border-[#d0d5dd]'
                }`}>
                {t === 'all' ? `All (${briefing.events.length})` : t === 'cve' ? `CVE / KEV (${kevCount})` : `Ransomware (${ransomCount})`}
              </button>
            ))}
          </div>

          {filteredEvents.length === 0 ? (
            <p className="text-sm text-[#98a2b3] px-1">No events match the selected filter.</p>
          ) : (
            <div className="space-y-2">
              {filteredEvents.map(event => (
                <EventCard key={event.id} event={event} />
              ))}
            </div>
          )}

          <p className="text-xs text-[#98a2b3] text-center pt-1">
            Sources:{' '}
            <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer" className="hover:text-[#667085] underline">CISA KEV</a>
            {' · '}
            <a href="https://www.ransomware.live" target="_blank" rel="noopener noreferrer" className="hover:text-[#667085] underline">Ransomware.live</a>
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
          <p className="text-xs text-[#98a2b3] text-center">
            Threat data from{' '}
            <a href="https://pulsedive.com" target="_blank" rel="noopener noreferrer" className="hover:text-[#667085] underline">pulsedive.com</a>
          </p>
        </div>
      )}

      {/* Pulsedive empty state */}
      {activeView === 'pulsedive' && !pulsediveData && !pulsediveLoading && !pulsediveError && (
        <p className="text-sm text-[#98a2b3] px-1">Click Refresh to load Pulsedive indicators.</p>
      )}
    </div>
  );
}
