import { useMemo, useState } from 'react';
import type { AnalysisResponse } from '../types/analysis';
import type { EnrichmentResult } from '../types/enrichment';
import { EnrichmentCard } from './EnrichmentCard';
import { CopyButton } from './CopyButton';
import { KeyFactsSummaryStrip, PivotSection, ContradictionBanner, ProviderComparisonPanel } from './enrichmentShared';
import { parseNarrative, buildSourceMap, findSourceUrl } from '../lib/narrative';

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4, benign: 5 };

const SEVERITY_STYLE: Record<string, { rule: string; text: string; label: string }> = {
  critical: { rule: 'bg-danger', text: 'text-danger-fg', label: 'Critical' },
  high:     { rule: 'bg-high',   text: 'text-high-fg',   label: 'High' },
  medium:   { rule: 'bg-warn',   text: 'text-warn-fg',   label: 'Medium' },
  low:      { rule: 'bg-accent', text: 'text-accent-fg', label: 'Low' },
  benign:   { rule: 'bg-ok',     text: 'text-ok-fg',     label: 'Benign' },
  unknown:  { rule: 'bg-fg-4',   text: 'text-fg-2',      label: 'Inconclusive' },
};

const hasData = (r: EnrichmentResult) => r.status === 'ok' || r.status === 'cached';

/** Plain-text summary suitable for pasting into a ticket. */
export function buildTicketSummary(response: AnalysisResponse): string {
  const { ioc, overall, results, contradictions, narrative } = response;
  const sev = SEVERITY_STYLE[overall.severity]?.label ?? overall.severity;
  const withData = results.filter(hasData);
  const parsed = narrative ? parseNarrative(narrative) : null;
  const lines = [
    `Indicator: ${ioc.normalised} (${ioc.type})`,
    `Severity: ${sev} · ${overall.confidence} confidence · ${withData.length}/${results.length} sources returned data`,
  ];
  if (parsed?.verdict) lines.push(`Local LLM verdict: ${parsed.verdict}`);
  if (overall.recommendedActions.length) lines.push('', 'Next steps:', ...overall.recommendedActions.map(a => `- ${a}`));
  if (parsed?.findings.length) lines.push('', 'Key findings:', ...parsed.findings.map(f => `- ${f}`));
  if (contradictions?.length) lines.push('', 'Source conflicts:', ...contradictions.map(c => `- ${c.message}`));
  lines.push('', 'Sources:', ...withData.map(r => `- ${r.providerName}: ${r.summary}`));
  lines.push('', `Analysed ${new Date(response.analysedAt).toISOString()}`);
  return lines.join('\n');
}

function Section({ title, aside, children }: { title: string; aside?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="space-y-2">
      <div className="flex items-center justify-between gap-3">
        <h2 className="wb-label">{title}</h2>
        {aside}
      </div>
      {children}
    </section>
  );
}

interface Props {
  response: AnalysisResponse;
  onPivot?: (value: string) => void;
}

/**
 * Verdict-first view of a completed analysis: computed severity and next steps, then
 * conflicts, key facts, the local LLM summary, pivots and per-provider detail.
 */
export function AnalysisResultView({ response, onPivot }: Props) {
  const { results, overall, contradictions, narrative, narrativeError, ollamaModel, analysedAt } = response;
  const [showProviders, setShowProviders] = useState(false);

  const parsed = useMemo(() => (narrative ? parseNarrative(narrative) : null), [narrative]);
  const sourceMap = useMemo(() => buildSourceMap(results), [results]);
  const sorted = useMemo(
    () => [...results].sort((a, b) => (SEVERITY_RANK[a.severity] ?? 4) - (SEVERITY_RANK[b.severity] ?? 4)),
    [results],
  );

  const withData = results.filter(hasData);
  const cachedCount = results.filter(r => r.status === 'cached' || r.fromCache).length;
  const style = SEVERITY_STYLE[overall.severity] ?? SEVERITY_STYLE['unknown']!;
  const resolvedIps = [...new Set(withData.flatMap(r => r.resolvedIps ?? []))];
  const relatedDomains = [...new Set(withData.flatMap(r => r.relatedDomains ?? []))];
  const unstructured = narrative && parsed && !parsed.verdict && parsed.findings.length === 0;

  return (
    <div className="space-y-6">
      {/* ── Verdict ─────────────────────────────────────────────────── */}
      <div className="flex gap-4">
        <span className={`w-1 rounded-full shrink-0 ${style.rule}`} aria-hidden />
        <div className="flex-1 min-w-0 space-y-3">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="text-[11px] text-fg-4">Severity</p>
              <p className={`text-[22px] leading-tight font-semibold ${style.text}`}>{style.label}</p>
              <p className="mt-1 text-xs text-fg-3">
                <span className="capitalize">{overall.confidence}</span> confidence
                <span className="text-fg-4"> · </span>
                {withData.length} of {results.length} sources returned data
                {cachedCount > 0 && <><span className="text-fg-4"> · </span>{cachedCount} from cache</>}
              </p>
              {parsed?.verdict && (
                <p className="mt-1 text-xs text-fg-3">
                  Local LLM verdict: <span className="font-medium text-fg-1">{parsed.verdict}</span>
                </p>
              )}
            </div>
            <CopyButton text={buildTicketSummary(response)} label="ticket summary" />
          </div>

          {overall.recommendedActions.length > 0 && (
            <ol className="space-y-1">
              {overall.recommendedActions.map((a, i) => (
                <li key={i} className="flex gap-2.5 text-[13px] text-fg-1">
                  <span className="w-4 text-right text-xs text-fg-4 tabular-nums pt-px">{i + 1}.</span>
                  <span>{a}</span>
                </li>
              ))}
            </ol>
          )}
        </div>
      </div>

      {(contradictions?.length ?? 0) > 0 && <ContradictionBanner contradictions={contradictions!} />}

      <KeyFactsSummaryStrip results={results} />

      {/* ── LLM summary ─────────────────────────────────────────────── */}
      {parsed && !unstructured && (parsed.findings.length > 0 || parsed.notes || parsed.actions.length > 0) && (
        <Section
          title="Summary"
          aside={<span className="text-[11px] text-fg-4">Written by {ollamaModel} on this machine · verify before acting</span>}
        >
          {parsed.findings.length > 0 && (
            <ul className="space-y-1.5">
              {parsed.findings.map((f, i) => {
                const src = findSourceUrl(f, sourceMap);
                return (
                  <li key={i} className="flex gap-2.5 text-[13px] text-fg-2 leading-relaxed">
                    <span className="mt-2 w-1 h-1 rounded-full bg-fg-4 shrink-0" />
                    <span className="flex-1">{f}</span>
                    {src && (
                      <a href={src} target="_blank" rel="noopener noreferrer" className="shrink-0 text-xs text-accent-fg hover:underline">
                        source
                      </a>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
          {parsed.actions.length > 0 && (
            <div className="pt-1">
              <p className="text-xs text-fg-4 mb-1">Suggested by the LLM</p>
              <ul className="space-y-1">
                {parsed.actions.map((a, i) => (
                  <li key={i} className="flex gap-2.5 text-[13px] text-fg-2"><span className="text-fg-4">–</span>{a}</li>
                ))}
              </ul>
            </div>
          )}
          {parsed.notes && (
            <p className="text-[13px] text-fg-2 leading-relaxed border-l-2 border-line pl-3">{parsed.notes}</p>
          )}
        </Section>
      )}
      {unstructured && (
        <Section title="Summary">
          <pre className="text-[13px] text-fg-2 whitespace-pre-wrap leading-relaxed font-sans">{narrative}</pre>
        </Section>
      )}
      {!narrative && narrativeError && (
        <p className="text-xs text-fg-4">
          No written summary: {narrativeError}
        </p>
      )}

      {/* ── Pivots ──────────────────────────────────────────────────── */}
      {onPivot && resolvedIps.length > 0 && (
        <PivotSection items={resolvedIps} label="Resolved IPs — click to investigate" color="blue" onPivot={onPivot} />
      )}
      {onPivot && relatedDomains.length > 0 && (
        <PivotSection items={relatedDomains} label="Certificate SANs — click to investigate" color="purple" onPivot={onPivot} />
      )}

      <ProviderComparisonPanel results={results} iocType={response.ioc.type} />

      {/* ── Provider detail ─────────────────────────────────────────── */}
      <section>
        <button
          onClick={() => setShowProviders(v => !v)}
          aria-expanded={showProviders}
          className="w-full flex items-center gap-2 text-left"
        >
          <svg className={`w-3 h-3 text-fg-4 transition-transform ${showProviders ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
          </svg>
          <span className="wb-label">Provider results</span>
          <span className="ml-auto text-[11px] text-fg-4">{withData.length} with data · {results.length - withData.length} without</span>
        </button>
        {showProviders && (
          <div className="mt-2 space-y-1.5">
            {sorted.map(r => <EnrichmentCard key={r.providerId} result={r} />)}
          </div>
        )}
      </section>

      <p className="text-[11px] font-mono text-fg-4">Analysed {new Date(analysedAt).toLocaleString()}</p>
    </div>
  );
}
