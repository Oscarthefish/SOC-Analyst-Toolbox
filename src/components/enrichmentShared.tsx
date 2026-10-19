import { useState, useCallback } from 'react';
import type { EnrichmentResult, ContradictionFlag } from '../types/enrichment';
import { extractSummaryFacts } from '../lib/summaryFacts';
import { buildComparison } from '../lib/providerComparison';

export const SEV_CHIP: Record<string, string> = {
  critical: 'bg-danger-bg border-danger-line text-danger-fg',
  high:     'bg-danger-bg border-danger-line text-danger-fg',
  medium:   'bg-warn-bg border-warn-line text-warn-fg',
  low:      'bg-accent-bg border-accent-line text-accent-fg',
  benign:   'bg-ok-bg border-ok-line text-ok-fg',
};

// ── KeyFactsSummaryStrip ───────────────────────────────────────────────────

export function KeyFactsSummaryStrip({ results }: { results: EnrichmentResult[] }) {
  const facts = extractSummaryFacts(results);
  if (facts.length === 0) return null;
  return (
    <div className="rounded-lg border border-line bg-inset px-3 py-2.5">
      <p className="text-[10px] font-semibold text-fg-4 uppercase tracking-wider mb-2">Key Facts</p>
      <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
        {facts.map((f, i) => (
          <div key={i} className="flex items-start gap-1.5 min-w-0">
            <span className="text-[11px] text-fg-3 shrink-0 w-20 truncate">{f.label}</span>
            <span className={`text-[11px] font-semibold truncate px-1.5 py-0 rounded border ${
              f.severity && SEV_CHIP[f.severity] ? SEV_CHIP[f.severity] : 'text-fg-1 border-transparent bg-transparent'
            }`}>
              {f.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── PivotSection ───────────────────────────────────────────────────────────

export function PivotSection({ items, label, color, onPivot }: {
  items: string[];
  label: string;
  color: 'blue' | 'purple';
  onPivot: (value: string) => void;
}) {
  const [showAll, setShowAll] = useState(false);
  const unique = Array.from(new Set(items));
  if (unique.length === 0) return null;
  const LIMIT = 6;
  const visible = showAll ? unique : unique.slice(0, LIMIT);
  const hidden = unique.length - LIMIT;

  const { bg, border, text, hover } = color === 'blue'
    ? { bg: 'bg-accent-bg', border: 'border-accent-line', text: 'text-accent-fg', hover: 'hover:bg-accent hover:text-white hover:border-accent' }
    : { bg: 'bg-violet-bg', border: 'border-violet-line', text: 'text-violet-fg', hover: 'hover:bg-violet hover:text-white hover:border-violet' };

  return (
    <div className={`rounded-lg border ${border} ${bg} px-3.5 py-2.5`}>
      <div className="flex items-center gap-2 mb-2">
        <svg className={`w-3.5 h-3.5 ${text} shrink-0`} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
          <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
        </svg>
        <p className={`text-[10px] font-semibold ${text} uppercase tracking-wider`}>{label}</p>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {visible.map(item => (
          <button
            key={item}
            onClick={() => onPivot(item)}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-surface border ${border} ${text} text-xs font-mono font-medium ${hover} transition-colors`}
            title={`Investigate ${item}`}
          >
            {item}
            <svg className="w-3 h-3 opacity-60" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 12h14M12 5l7 7-7 7" />
            </svg>
          </button>
        ))}
        {!showAll && hidden > 0 && (
          <button
            onClick={() => setShowAll(true)}
            className={`px-2.5 py-1 rounded-md bg-surface border ${border} ${text} text-xs font-medium hover:bg-inset transition-colors`}
          >
            +{hidden} more
          </button>
        )}
      </div>
    </div>
  );
}

// ── ContradictionBanner ────────────────────────────────────────────────────

export function ContradictionBanner({ contradictions }: { contradictions: ContradictionFlag[] }) {
  const [expanded, setExpanded] = useState(false);
  if (contradictions.length === 0) return null;
  return (
    <div className="rounded-lg border border-warn-line bg-warn-bg overflow-hidden">
      <button
        onClick={() => setExpanded(v => !v)}
        className="w-full flex items-center gap-2.5 px-3.5 py-2.5 text-left hover:bg-warn-bg transition-colors"
      >
        <svg className="w-4 h-4 text-warn-fg shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
        </svg>
        <span className="text-xs font-semibold text-warn-fg flex-1">
          {contradictions.length} source conflict{contradictions.length > 1 ? 's' : ''} detected — review before acting
        </span>
        <svg className={`w-3.5 h-3.5 text-warn-fg transition-transform ${expanded ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {expanded && (
        <div className="px-3.5 pb-3 space-y-3 border-t border-warn-line">
          {contradictions.map((c, i) => (
            <div key={i} className="pt-3">
              <p className="text-xs font-semibold text-warn-fg font-mono mb-1">{c.type}</p>
              <p className="text-xs text-warn-fg mb-1">{c.message}</p>
              <p className="text-xs text-warn-fg opacity-80">→ {c.recommendation}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Provider Comparison Panel ──────────────────────────────────────────────

export function ProviderComparisonPanel({ results, iocType }: { results: EnrichmentResult[]; iocType: string }) {
  const [copied, setCopied] = useState(false);
  const groups = buildComparison(results, iocType);

  const handleCopy = useCallback(() => {
    const lines: string[] = [];
    groups.forEach(g => {
      lines.push(g.label.toUpperCase());
      g.rows.forEach(r => {
        const sev = r.severity && r.severity !== 'unknown' ? ` [${r.severity.toUpperCase()}]` : '';
        lines.push(`  ${r.provider}: ${r.value}${sev}`);
      });
      lines.push('');
    });
    void navigator.clipboard.writeText(lines.join('\n').trim()).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [groups]);

  if (groups.length === 0) return null;

  return (
    <div className="rounded-lg border border-line overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 bg-inset border-b border-line-soft">
        <p className="text-[11px] font-bold uppercase tracking-wider text-fg-3">Provider Intel Summary</p>
        <button
          onClick={handleCopy}
          title="Copy summary"
          className="flex items-center gap-1 text-[11px] text-fg-3 hover:text-fg-2 font-medium transition-colors"
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
      </div>

      {/* Groups */}
      <div className="divide-y divide-line-soft">
        {groups.map(g => (
          <div key={g.label} className="px-3 py-2.5">
            <p className="text-[9px] font-bold uppercase tracking-widest text-fg-4 mb-2">{g.label}</p>
            <div className="space-y-1.5">
              {g.rows.map((row, i) => (
                <div key={i} className={`flex items-start gap-2 text-[11px] rounded px-1.5 py-1 -mx-1.5 ${row.highlight ? 'bg-warn-bg' : ''}`}>
                  {/* Provider name */}
                  <span className="w-[80px] shrink-0 font-semibold text-fg-2 truncate">{row.provider}</span>

                  {/* Value */}
                  <span className="flex-1 text-fg-2 break-words leading-snug min-w-0">
                    {row.value}
                    {row.note && <span className="ml-1 text-fg-4">({row.note})</span>}
                    {row.highlight && (
                      <svg className="inline w-3 h-3 text-warn-fg ml-1 shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01M12 3l9 16H3L12 3z" />
                      </svg>
                    )}
                  </span>

                  {/* Severity chip */}
                  {row.severity && row.severity !== 'unknown' && (
                    <span className={`shrink-0 text-[9px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded border ${SEV_CHIP[row.severity] ?? ''}`}>
                      {row.severity}
                    </span>
                  )}

                  {/* Source link */}
                  {row.url && (
                    <a href={row.url} target="_blank" rel="noopener noreferrer" title="View source"
                      className="shrink-0 text-fg-4 hover:text-accent-fg transition-colors">
                      <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
                        <polyline points="15 3 21 3 21 9" /><line x1="10" y1="14" x2="21" y2="3" />
                      </svg>
                    </a>
                  )}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
