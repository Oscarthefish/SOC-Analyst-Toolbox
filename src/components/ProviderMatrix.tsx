import { useMemo, useState } from 'react';
import type { EnrichmentResult } from '../types/enrichment';
import { EnrichmentCard } from './EnrichmentCard';
import { BUCKET_ORDER, BUCKET_LABEL, bucketOf } from '../lib/severityMix';
import type { Bucket } from '../lib/severityMix';

/**
 * Every provider as a tile coloured by what it said, worst first. Selecting a
 * tile opens that provider's full result underneath; "Show all" lists them all.
 */

const TILE: Record<Bucket, { tile: string; rule: string; label: string }> = {
  critical: { tile: 'bg-danger-bg border-danger-line', rule: 'bg-danger', label: 'text-danger-fg' },
  high:     { tile: 'bg-high-bg border-high-line',     rule: 'bg-high',   label: 'text-high-fg' },
  medium:   { tile: 'bg-warn-bg border-warn-line',     rule: 'bg-warn',   label: 'text-warn-fg' },
  low:      { tile: 'bg-c1-bg border-line',            rule: 'bg-c1',     label: 'text-c1-fg' },
  benign:   { tile: 'bg-ok-bg border-ok-line',         rule: 'bg-ok',     label: 'text-ok-fg' },
  info:     { tile: 'bg-surface border-line',          rule: 'bg-line-strong', label: 'text-fg-3' },
  none:     { tile: 'bg-inset border-line-soft border-dashed', rule: 'bg-transparent', label: 'text-fg-4' },
};

const NO_DATA_REASON: Record<string, string> = {
  missing_key: 'No API key', unsupported_ioc: 'Not applicable', rate_limited: 'Rate limited',
  error: 'Error', skipped_safety: 'Skipped for safety',
};

export function ProviderMatrix({ results }: { results: EnrichmentResult[] }) {
  const [selected, setSelected] = useState<string | null>(null);
  const [showAll, setShowAll] = useState(false);

  const sorted = useMemo(
    () => [...results].sort((a, b) => BUCKET_ORDER.indexOf(bucketOf(a)) - BUCKET_ORDER.indexOf(bucketOf(b)) || a.providerName.localeCompare(b.providerName)),
    [results],
  );
  const current = sorted.find(r => r.providerId === selected) ?? null;

  return (
    <section className="space-y-2">
      <div className="flex items-center justify-between gap-3">
        <h2 className="wb-label">Provider verdicts</h2>
        <button
          onClick={() => { setShowAll(v => !v); setSelected(null); }}
          aria-expanded={showAll}
          className="text-[11px] font-medium text-accent-fg hover:underline"
        >
          {showAll ? 'Hide details' : 'Show all details'}
        </button>
      </div>

      <div className="grid gap-1.5 grid-cols-[repeat(auto-fill,minmax(150px,1fr))]">
        {sorted.map(r => {
          const b = bucketOf(r);
          const t = TILE[b];
          const active = selected === r.providerId;
          return (
            <button
              key={r.providerId}
              onClick={() => { setSelected(active ? null : r.providerId); setShowAll(false); }}
              aria-pressed={active}
              title={r.summary}
              className={`relative text-left rounded-md border pl-3 pr-2 py-1.5 overflow-hidden transition-shadow ${t.tile} ${
                active ? 'ring-2 ring-accent ring-offset-1 ring-offset-surface' : 'hover:shadow-sm'
              }`}
            >
              <span className={`absolute left-0 top-0 bottom-0 w-[3px] ${t.rule}`} aria-hidden />
              <span className={`block text-[12px] font-medium truncate ${b === 'none' ? 'text-fg-3' : 'text-fg-1'}`}>{r.providerName}</span>
              <span className={`block text-[11px] truncate ${t.label}`}>
                {b === 'none' ? NO_DATA_REASON[r.status] ?? 'No data' : BUCKET_LABEL[b]}
                {r.fromCache || r.status === 'cached' ? <span className="text-fg-4"> · cached</span> : null}
              </span>
            </button>
          );
        })}
      </div>

      {current && !showAll && (
        <div className="pt-1"><EnrichmentCard result={current} /></div>
      )}
      {showAll && (
        <div className="space-y-1.5 pt-1">
          {sorted.map(r => <EnrichmentCard key={r.providerId} result={r} />)}
        </div>
      )}
    </section>
  );
}
