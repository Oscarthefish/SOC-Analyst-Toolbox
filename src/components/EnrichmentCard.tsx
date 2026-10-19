import { useState, useCallback } from 'react';
import type { EnrichmentResult, EnrichmentStatus, Severity, FreshnessLabel, SourceTier } from '../types/enrichment';

interface EnrichmentCardProps {
  result: EnrichmentResult;
}

function statusDot(status: EnrichmentStatus) {
  const map: Record<EnrichmentStatus, string> = {
    ok:               'bg-ok',
    cached:           'bg-ok',
    missing_key:      'bg-fg-4',
    unsupported_ioc:  'bg-fg-4',
    rate_limited:     'bg-warn',
    error:            'bg-danger',
    skipped_safety:   'bg-warn',
  };
  return map[status] ?? 'bg-fg-4';
}

function statusLabel(status: EnrichmentStatus) {
  const map: Record<EnrichmentStatus, string> = {
    ok: 'OK', cached: 'Cached', missing_key: 'No key',
    unsupported_ioc: 'Unsupported', rate_limited: 'Rate limited',
    error: 'Error', skipped_safety: 'Skipped',
  };
  return map[status] ?? status;
}

function CopyUrlButton({ url }: { url: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = useCallback(() => {
    void navigator.clipboard.writeText(url).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [url]);

  return (
    <button
      onClick={handleCopy}
      title="Copy link"
      className="text-[11px] text-fg-3 hover:text-fg-2 font-medium flex items-center gap-1 transition-colors"
    >
      {copied ? (
        <>
          <svg className="w-3 h-3 text-ok-fg" fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
          </svg>
          <span className="text-ok-fg">Copied</span>
        </>
      ) : (
        <>
          <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth={1.8} viewBox="0 0 24 24">
            <rect x="9" y="9" width="13" height="13" rx="2" />
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
          </svg>
          Copy
        </>
      )}
    </button>
  );
}

function SeverityChip({ severity }: { severity: Severity }) {
  const map: Record<Severity, { cls: string; label: string }> = {
    benign:   { cls: 'bg-ok-bg border-ok-line text-ok-fg', label: 'Benign' },
    low:      { cls: 'bg-accent-bg border-accent-line text-accent-fg', label: 'Low' },
    medium:   { cls: 'bg-warn-bg border-warn-line text-warn-fg', label: 'Medium' },
    high:     { cls: 'bg-danger-bg border-danger-line text-danger-fg', label: 'High' },
    critical: { cls: 'bg-danger-bg border-danger text-danger-fg font-bold', label: 'Critical' },
    unknown:  { cls: 'bg-raised border-line text-fg-3', label: 'Unknown' },
  };
  const s = map[severity] ?? map.unknown;
  return <span className={`text-[11px] px-2 py-0.5 rounded-md border font-semibold ${s.cls}`}>{s.label}</span>;
}

function FreshnessBadge({ label }: { label: FreshnessLabel }) {
  const map: Record<FreshnessLabel, { cls: string; text: string }> = {
    last24h:   { cls: 'bg-ok-bg border-ok-line text-ok-fg', text: 'Active' },
    last7d:    { cls: 'bg-accent-bg border-accent-line text-accent-fg', text: '7d' },
    last30d:   { cls: 'bg-raised border-line text-fg-2', text: '30d' },
    historical:{ cls: 'bg-warn-bg border-warn-line text-warn-fg', text: 'Historical' },
    unknown:   { cls: 'bg-raised border-line text-fg-4', text: '?' },
  };
  const s = map[label] ?? map.unknown;
  return (
    <span className={`text-[10px] px-1.5 py-0.5 rounded border font-mono ${s.cls}`}>{s.text}</span>
  );
}

function TierBadge({ tier }: { tier: SourceTier }) {
  const map: Record<SourceTier, { cls: string; text: string }> = {
    'authoritative':  { cls: 'bg-accent-bg border-accent-line text-accent-fg', text: 'Auth' },
    'commercial-ti':  { cls: 'bg-violet-bg border-violet-line text-violet-fg', text: 'TI' },
    'community':      { cls: 'bg-raised border-line text-fg-2', text: 'Rep' },
    'reputation':     { cls: 'bg-raised border-line text-fg-2', text: 'Rep' },
    'passive-infra':  { cls: 'bg-inset border-line-soft text-fg-4', text: 'Infra' },
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
          <tr key={i} className="border-t border-line-soft">
            <td className="py-1 pr-3 text-fg-4 font-medium whitespace-nowrap align-top w-1/3">{f.label}</td>
            <td className="py-1 text-fg-2 break-all">
              {f.value}
              {f.timestamp && <span className="text-fg-4 ml-1 font-mono text-[10px]">({f.timestamp.split('T')[0]})</span>}
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
          <tr key={key} className="border-t border-line-soft">
            <td className="py-1 pr-3 text-fg-4 font-mono whitespace-nowrap align-top w-1/3">{key}</td>
            <td className="py-1 text-fg-2 break-all">
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
    <div className={`border rounded-lg overflow-hidden ${hasData ? 'border-line bg-surface' : 'border-line-soft bg-inset opacity-60'}`}>
      <button
        onClick={() => hasData && setExpanded(v => !v)}
        className={`w-full flex items-center gap-3 px-3 py-2.5 text-left ${hasData ? 'hover:bg-inset' : 'cursor-default'} transition-colors`}
      >
        <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${statusDot(result.status)}`} />
        <span className="text-[13px] font-semibold text-fg-2 flex-1 min-w-0 truncate">{result.providerName}</span>

        <div className="flex items-center gap-1.5 shrink-0">
          {hasData && result.sourceReliability && <TierBadge tier={result.sourceReliability} />}
          {hasData && result.freshnessLabel && result.freshnessLabel !== 'unknown' && (
            <FreshnessBadge label={result.freshnessLabel} />
          )}
          {hasData && <SeverityChip severity={result.severity} />}
          {result.fromCache && (
            <span className="text-[10px] font-mono text-fg-4 bg-raised px-1.5 py-0.5 rounded border border-line">
              cached
            </span>
          )}
          <span className={`text-[11px] font-medium px-1.5 py-0.5 rounded border ${
            hasData ? 'bg-raised border-line text-fg-3' : 'bg-transparent border-transparent text-fg-4'
          }`}>
            {statusLabel(result.status)}
          </span>
          {hasData && (
            <svg className={`w-3.5 h-3.5 text-fg-4 transition-transform ${expanded ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
            </svg>
          )}
        </div>
      </button>

      {/* Summary always visible if has data */}
      {hasData && result.summary && !expanded && (
        <p className="px-3 pb-2.5 text-xs text-fg-3 leading-relaxed border-t border-line-soft pt-2">{result.summary}</p>
      )}

      {/* Expanded detail */}
      {expanded && hasData && (
        <div className="px-3 pb-3 border-t border-line-soft pt-2 space-y-2">
          {result.summary && <p className="text-xs text-fg-2 leading-relaxed">{result.summary}</p>}
          {result.errorMessage && <p className="text-xs text-danger-fg font-mono">Error: {result.errorMessage}</p>}
          {result.keyFacts && result.keyFacts.length > 0
            ? <KeyFactsTable facts={result.keyFacts} />
            : Object.keys(result.data).length > 0 && <DataTable data={result.data} />
          }
          <div className="flex items-center justify-between pt-1 border-t border-line-soft">
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono text-fg-4">{checkedAt}</span>
              {result.firstSeenDate && (
                <span className="text-[10px] text-fg-4">
                  first seen {result.firstSeenDate.split('T')[0]}
                </span>
              )}
            </div>
            {result.sourceUrl && (
              <div className="flex items-center gap-2">
                <CopyUrlButton url={result.sourceUrl} />
                <a href={result.sourceUrl} target="_blank" rel="noopener noreferrer"
                  className="text-[11px] text-accent-fg hover:text-accent-fg font-medium flex items-center gap-1">
                  View ↗
                </a>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Error / no-data summary */}
      {!hasData && result.summary && (
        <p className="px-3 pb-2 text-[11px] text-fg-4 border-t border-line-soft pt-1.5">{result.summary}</p>
      )}
    </div>
  );
}
