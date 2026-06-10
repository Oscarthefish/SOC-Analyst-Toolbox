import { useState } from 'react';
import type { EnrichmentResult, EnrichmentStatus, Severity, FreshnessLabel, SourceTier } from '../types/enrichment';

interface EnrichmentCardProps {
  result: EnrichmentResult;
}

function statusDot(status: EnrichmentStatus) {
  const map: Record<EnrichmentStatus, string> = {
    ok:               'bg-[#079455]',
    cached:           'bg-[#079455]',
    missing_key:      'bg-[#98a2b3]',
    unsupported_ioc:  'bg-[#98a2b3]',
    rate_limited:     'bg-[#dc6803]',
    error:            'bg-[#d92d20]',
    skipped_safety:   'bg-[#dc6803]',
  };
  return map[status] ?? 'bg-[#98a2b3]';
}

function statusLabel(status: EnrichmentStatus) {
  const map: Record<EnrichmentStatus, string> = {
    ok: 'OK', cached: 'Cached', missing_key: 'No key',
    unsupported_ioc: 'Unsupported', rate_limited: 'Rate limited',
    error: 'Error', skipped_safety: 'Skipped',
  };
  return map[status] ?? status;
}

function SeverityChip({ severity }: { severity: Severity }) {
  const map: Record<Severity, { cls: string; label: string }> = {
    benign:   { cls: 'bg-[#ecfdf3] border-[#abefc6] text-[#067647]', label: 'Benign' },
    low:      { cls: 'bg-[#eff8ff] border-[#b2ddff] text-[#175cd3]', label: 'Low' },
    medium:   { cls: 'bg-[#fffaeb] border-[#fedf89] text-[#b54708]', label: 'Medium' },
    high:     { cls: 'bg-[#fef3f2] border-[#fecdca] text-[#b42318]', label: 'High' },
    critical: { cls: 'bg-[#fef3f2] border-[#d92d20] text-[#b42318] font-bold', label: 'Critical' },
    unknown:  { cls: 'bg-[#f2f4f7] border-[#e4e7ec] text-[#667085]', label: 'Unknown' },
  };
  const s = map[severity] ?? map.unknown;
  return <span className={`text-[11px] px-2 py-0.5 rounded-md border font-semibold ${s.cls}`}>{s.label}</span>;
}

function FreshnessBadge({ label }: { label: FreshnessLabel }) {
  const map: Record<FreshnessLabel, { cls: string; text: string }> = {
    last24h:   { cls: 'bg-[#ecfdf3] border-[#abefc6] text-[#067647]', text: 'Active' },
    last7d:    { cls: 'bg-[#eff8ff] border-[#b2ddff] text-[#175cd3]', text: '7d' },
    last30d:   { cls: 'bg-[#f2f4f7] border-[#e4e7ec] text-[#475467]', text: '30d' },
    historical:{ cls: 'bg-[#fffaeb] border-[#fedf89] text-[#b54708]', text: 'Historical' },
    unknown:   { cls: 'bg-[#f2f4f7] border-[#e4e7ec] text-[#98a2b3]', text: '?' },
  };
  const s = map[label] ?? map.unknown;
  return (
    <span className={`text-[10px] px-1.5 py-0.5 rounded border font-mono ${s.cls}`}>{s.text}</span>
  );
}

function TierBadge({ tier }: { tier: SourceTier }) {
  const map: Record<SourceTier, { cls: string; text: string }> = {
    'authoritative':  { cls: 'bg-[#eff8ff] border-[#b2ddff] text-[#175cd3]', text: 'Auth' },
    'commercial-ti':  { cls: 'bg-[#f4f3ff] border-[#d9d6fe] text-[#5925dc]', text: 'TI' },
    'community':      { cls: 'bg-[#f2f4f7] border-[#e4e7ec] text-[#475467]', text: 'Rep' },
    'reputation':     { cls: 'bg-[#f2f4f7] border-[#e4e7ec] text-[#475467]', text: 'Rep' },
    'passive-infra':  { cls: 'bg-[#fafbfc] border-[#f2f4f7] text-[#98a2b3]', text: 'Infra' },
  };
  const s = map[tier] ?? map['community'];
  return (
    <span className={`text-[10px] px-1.5 py-0.5 rounded border font-semibold ${s.cls}`}>{s.text}</span>
  );
}

function KeyFactsTable({ facts }: { facts: { label: string; value: string; timestamp?: string }[] }) {
  if (facts.length === 0) return null;
  return (
    <table className="w-full text-xs mt-2">
      <tbody>
        {facts.map((f, i) => (
          <tr key={i} className="border-t border-[#f2f4f7]">
            <td className="py-1 pr-3 text-[#98a2b3] font-medium whitespace-nowrap align-top w-1/3">{f.label}</td>
            <td className="py-1 text-[#344054] break-all">
              {f.value}
              {f.timestamp && <span className="text-[#98a2b3] ml-1 font-mono text-[10px]">({f.timestamp.split('T')[0]})</span>}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function DataTable({ data }: { data: Record<string, unknown> }) {
  const entries = Object.entries(data).filter(([, v]) => v !== null && v !== undefined && v !== '');
  if (entries.length === 0) return null;
  return (
    <table className="w-full text-xs mt-2">
      <tbody>
        {entries.map(([key, value]) => (
          <tr key={key} className="border-t border-[#f2f4f7]">
            <td className="py-1 pr-3 text-[#98a2b3] font-mono whitespace-nowrap align-top w-1/3">{key}</td>
            <td className="py-1 text-[#344054] break-all">
              {Array.isArray(value) ? (value as unknown[]).join(', ') : String(value)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function EnrichmentCard({ result }: EnrichmentCardProps) {
  const [expanded, setExpanded] = useState(false);
  const checkedAt = new Date(result.checkedAt).toLocaleTimeString();
  const hasData = result.status === 'ok' || result.status === 'cached';

  return (
    <div className={`border rounded-[10px] overflow-hidden ${hasData ? 'border-[#e4e7ec] bg-white' : 'border-[#f2f4f7] bg-[#fafbfc] opacity-60'}`}>
      <button
        onClick={() => hasData && setExpanded(v => !v)}
        className={`w-full flex items-center gap-3 px-3 py-2.5 text-left ${hasData ? 'hover:bg-[#f9fafb]' : 'cursor-default'} transition-colors`}
      >
        <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${statusDot(result.status)}`} />
        <span className="text-[13px] font-semibold text-[#344054] flex-1 min-w-0 truncate">{result.providerName}</span>

        <div className="flex items-center gap-1.5 shrink-0">
          {hasData && result.sourceReliability && <TierBadge tier={result.sourceReliability} />}
          {hasData && result.freshnessLabel && result.freshnessLabel !== 'unknown' && (
            <FreshnessBadge label={result.freshnessLabel} />
          )}
          {hasData && <SeverityChip severity={result.severity} />}
          {result.fromCache && (
            <span className="text-[10px] font-mono text-[#98a2b3] bg-[#f2f4f7] px-1.5 py-0.5 rounded border border-[#e4e7ec]">
              cached
            </span>
          )}
          <span className={`text-[11px] font-medium px-1.5 py-0.5 rounded border ${
            hasData ? 'bg-[#f2f4f7] border-[#e4e7ec] text-[#667085]' : 'bg-transparent border-transparent text-[#98a2b3]'
          }`}>
            {statusLabel(result.status)}
          </span>
          {hasData && (
            <svg className={`w-3.5 h-3.5 text-[#98a2b3] transition-transform ${expanded ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
            </svg>
          )}
        </div>
      </button>

      {/* Summary always visible if has data */}
      {hasData && result.summary && !expanded && (
        <p className="px-3 pb-2.5 text-xs text-[#667085] leading-relaxed border-t border-[#f2f4f7] pt-2">{result.summary}</p>
      )}

      {/* Expanded detail */}
      {expanded && hasData && (
        <div className="px-3 pb-3 border-t border-[#f2f4f7] pt-2 space-y-2">
          {result.summary && <p className="text-xs text-[#475467] leading-relaxed">{result.summary}</p>}
          {result.errorMessage && <p className="text-xs text-[#d92d20] font-mono">Error: {result.errorMessage}</p>}
          {result.keyFacts && result.keyFacts.length > 0
            ? <KeyFactsTable facts={result.keyFacts} />
            : Object.keys(result.data).length > 0 && <DataTable data={result.data} />
          }
          <div className="flex items-center justify-between pt-1 border-t border-[#f2f4f7]">
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono text-[#98a2b3]">{checkedAt}</span>
              {result.firstSeenDate && (
                <span className="text-[10px] text-[#98a2b3]">
                  first seen {result.firstSeenDate.split('T')[0]}
                </span>
              )}
            </div>
            {result.sourceUrl && (
              <a href={result.sourceUrl} target="_blank" rel="noopener noreferrer"
                className="text-[11px] text-[#1570ef] hover:text-[#175cd3] font-medium flex items-center gap-1">
                View ↗
              </a>
            )}
          </div>
        </div>
      )}

      {/* Error / no-data summary */}
      {!hasData && result.summary && (
        <p className="px-3 pb-2 text-[11px] text-[#98a2b3] border-t border-[#f2f4f7] pt-1.5">{result.summary}</p>
      )}
    </div>
  );
}
