import { useState } from 'react';
import type { AnalysisResponse } from '../types/analysis';
import type { EnrichmentResult } from '../types/enrichment';
import { EnrichmentCard } from './EnrichmentCard';
import { KeyFactsSummaryStrip, PivotSection, ContradictionBanner, ProviderComparisonPanel } from './enrichmentShared';

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4, benign: 5 };
function sortBySeverity(results: EnrichmentResult[]): EnrichmentResult[] {
  return [...results].sort((a, b) => (SEVERITY_RANK[a.severity] ?? 4) - (SEVERITY_RANK[b.severity] ?? 4));
}

interface AnalysisResultsPanelProps {
  response: AnalysisResponse;
  onPivot?: (iocValue: string) => void;
}

const SEV_BAR: Record<string, { bar: string; text: string }> = {
  critical: { bar: 'bg-danger-bg border-danger-line', text: 'text-danger-fg' },
  high:     { bar: 'bg-danger-bg border-danger-line', text: 'text-danger-fg' },
  medium:   { bar: 'bg-warn-bg border-warn-line', text: 'text-warn-fg' },
  low:      { bar: 'bg-accent-bg border-accent-line', text: 'text-accent-fg' },
  benign:   { bar: 'bg-ok-bg border-ok-line', text: 'text-ok-fg' },
  unknown:  { bar: 'bg-raised border-line', text: 'text-fg-2' },
};

export function AnalysisResultsPanel({ response, onPivot }: AnalysisResultsPanelProps) {
  const [showCards, setShowCards] = useState(false);

  const { results, overall, contradictions } = response;
  const ok = results.filter(r => r.status === 'ok' || r.status === 'cached');

  const resolvedIps = results
    .filter(r => r.status === 'ok' || r.status === 'cached')
    .flatMap(r => r.resolvedIps ?? []);

  const relatedDomains = results
    .filter(r => r.status === 'ok' || r.status === 'cached')
    .flatMap(r => r.relatedDomains ?? []);

  const sev = overall.severity ?? 'unknown';
  const style = SEV_BAR[sev] ?? SEV_BAR['unknown']!;

  return (
    <div className="wb-card p-5 space-y-4">
      {/* Header: overall severity */}
      <div className={`rounded-lg border px-4 py-3 ${style.bar}`}>
        <div className="flex flex-wrap items-center gap-2 mb-1">
          <span className="text-[11px] font-bold uppercase tracking-wider opacity-60">Enrichment Result</span>
          <span className={`font-semibold capitalize ${style.text}`}>{sev}</span>
          <span className="opacity-60 text-[11px]">· confidence {overall.confidence}</span>
          <span className="opacity-50 text-[11px] ml-auto">{ok.length}/{results.length} providers returned data</span>
        </div>
        <p className={`text-xs opacity-80 ${style.text}`}>{overall.summary}</p>
        {overall.recommendedActions.length > 0 && (
          <ul className="mt-2 space-y-0.5">
            {overall.recommendedActions.map((a, i) => (
              <li key={i} className={`flex gap-1.5 text-xs opacity-75 ${style.text}`}>
                <span className="opacity-50">·</span>{a}
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Key facts at a glance */}
      <KeyFactsSummaryStrip results={results} />

      {/* Cross-provider comparison */}
      <ProviderComparisonPanel results={results} iocType={response.ioc.type} />

      {/* Pivot chips */}
      {onPivot && resolvedIps.length > 0 && (
        <PivotSection
          items={resolvedIps}
          label="Resolved IPs — click to investigate"
          color="blue"
          onPivot={onPivot}
        />
      )}
      {onPivot && relatedDomains.length > 0 && (
        <PivotSection
          items={relatedDomains}
          label="Certificate SANs — click to investigate"
          color="purple"
          onPivot={onPivot}
        />
      )}

      {/* Contradiction banners */}
      {(contradictions?.length ?? 0) > 0 && (
        <ContradictionBanner contradictions={contradictions!} />
      )}

      {/* Provider cards (collapsible) */}
      <div>
        <button
          onClick={() => setShowCards(v => !v)}
          className="flex items-center gap-1.5 w-full text-left"
        >
          <svg className={`w-3 h-3 text-fg-4 transition-transform ${showCards ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
          </svg>
          <span className="text-[11px] font-semibold text-fg-4 uppercase tracking-wider">
            Provider Results ({results.length})
          </span>
          <span className="ml-auto text-[11px] text-fg-4">
            {ok.length} with data
          </span>
        </button>
        {showCards && (
          <div className="mt-2 space-y-1.5">
            {sortBySeverity(results).map(result => (
              <EnrichmentCard key={result.providerId} result={result} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
