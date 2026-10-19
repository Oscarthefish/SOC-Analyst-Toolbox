import { useMemo } from 'react';
import type { AnalysisResponse } from '../types/analysis';
import { CopyButton } from './CopyButton';
import { KeyFactsSummaryStrip, PivotSection, ContradictionBanner, ProviderComparisonPanel } from './enrichmentShared';
import { RelationshipGraph } from './RelationshipGraph';
import { ProviderMatrix } from './ProviderMatrix';
import { AttackPanel } from './AttackPanel';
import { deriveTechniques } from '../lib/attackMapping';
import { RingGauge, SeverityBar, SeverityLegend } from './charts';
import { parseNarrative, buildSourceMap, findSourceUrl } from '../lib/narrative';
import { hasData, severityMix, flaggedCount } from '../lib/severityMix';

const SEVERITY_STYLE: Record<string, { band: string; ring: string; text: string; label: string }> = {
  critical: { band: 'bg-danger-bg border-danger-line', ring: 'stroke-danger', text: 'text-danger-fg', label: 'Critical' },
  high:     { band: 'bg-high-bg border-high-line',     ring: 'stroke-high',   text: 'text-high-fg',   label: 'High' },
  medium:   { band: 'bg-warn-bg border-warn-line',     ring: 'stroke-warn',   text: 'text-warn-fg',   label: 'Medium' },
  low:      { band: 'bg-c1-bg border-line',            ring: 'stroke-c1',     text: 'text-c1-fg',     label: 'Low' },
  benign:   { band: 'bg-ok-bg border-ok-line',         ring: 'stroke-ok',     text: 'text-ok-fg',     label: 'Benign' },
  unknown:  { band: 'bg-inset border-line',            ring: 'stroke-fg-4',   text: 'text-fg-2',      label: 'Inconclusive' },
};

/** Related hosts beyond this many are listed in full under the graph. */
const GRAPH_HOST_LIMIT = 6;

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
  /** Workflow in use, for ATT&CK context */
  workflow?: { id: string; name: string } | null;
  /** Open the Hunt page with these techniques and this indicator */
  onHunt?: (techniqueIds: string[]) => void;
}

/**
 * Verdict-first view of a completed analysis: computed severity and next steps, then
 * conflicts, key facts, the local LLM summary, pivots and per-provider detail.
 */
export function AnalysisResultView({ response, onPivot, workflow, onHunt }: Props) {
  const { results, overall, contradictions, narrative, narrativeError, ollamaModel, analysedAt } = response;

  const parsed = useMemo(() => (narrative ? parseNarrative(narrative) : null), [narrative]);
  const sourceMap = useMemo(() => buildSourceMap(results), [results]);
  const mix = useMemo(() => severityMix(results), [results]);
  const techniques = useMemo(() => deriveTechniques(results, workflow), [results, workflow]);

  const withData = results.filter(hasData);
  const flagged = flaggedCount(results);
  const cachedCount = results.filter(r => r.status === 'cached' || r.fromCache).length;
  const style = SEVERITY_STYLE[overall.severity] ?? SEVERITY_STYLE['unknown']!;
  const resolvedIps = [...new Set(withData.flatMap(r => r.resolvedIps ?? []))];
  const relatedDomains = [...new Set(withData.flatMap(r => r.relatedDomains ?? []))];
  const unstructured = narrative && parsed && !parsed.verdict && parsed.findings.length === 0;

  return (
    <div className="space-y-6">
      {/* ── Verdict ─────────────────────────────────────────────────── */}
      <div className={`rounded-xl border p-4 sm:p-5 grid gap-5 lg:grid-cols-[auto_minmax(0,1fr)_260px] items-start ${style.band}`}>
        <RingGauge
          fraction={withData.length ? flagged / withData.length : 0}
          tone={style.ring}
          size={104}
          thickness={9}
          label={`${flagged} of ${withData.length} sources with data rate this medium or worse`}
        >
          <div className="leading-none">
            <p className="text-[26px] font-semibold text-fg-1 tabular-nums">{flagged}<span className="text-[15px] text-fg-4">/{withData.length}</span></p>
            <p className="mt-1 text-[10px] uppercase tracking-[.06em] text-fg-3">flag it</p>
          </div>
        </RingGauge>

        <div className="min-w-0 space-y-3">
          <div>
            <p className="text-[11px] uppercase tracking-[.06em] text-fg-3">Severity</p>
            <p className={`text-[26px] leading-tight font-semibold ${style.text}`}>{style.label}</p>
            <p className="mt-1 text-xs text-fg-2">
              <span className="capitalize">{overall.confidence}</span> confidence
              <span className="text-fg-4"> · </span>
              {withData.length} of {results.length} sources returned data
              {cachedCount > 0 && <><span className="text-fg-4"> · </span>{cachedCount} from cache</>}
            </p>
            {parsed?.verdict && (
              <p className="mt-1 text-xs text-fg-2">
                Local LLM verdict: <span className="font-medium text-fg-1">{parsed.verdict}</span>
              </p>
            )}
          </div>

          {overall.recommendedActions.length > 0 && (
            <ol className="space-y-1.5">
              {overall.recommendedActions.map((a, i) => (
                <li key={i} className="flex gap-2.5 text-[13px] text-fg-1">
                  <span className="w-5 h-5 shrink-0 grid place-items-center rounded-full bg-surface border border-line text-[11px] font-medium text-fg-2 tabular-nums">{i + 1}</span>
                  <span className="pt-px">{a}</span>
                </li>
              ))}
            </ol>
          )}
        </div>

        <div className="space-y-3 rounded-lg bg-surface border border-line p-3">
          <div className="flex items-center justify-between gap-2">
            <p className="text-[11px] font-medium text-fg-2">Source verdicts</p>
            <span className="text-[11px] text-fg-4 tabular-nums">{results.length} queried</span>
          </div>
          <SeverityBar mix={mix} label="Provider verdicts" />
          <SeverityLegend mix={mix} />
          <div className="pt-1 border-t border-line-soft">
            <CopyButton text={buildTicketSummary(response)} label="ticket summary" />
          </div>
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

      <RelationshipGraph results={results} indicator={response.ioc.normalised} onPivot={onPivot} />

      {/* Full host lists when there are more than the graph shows */}
      {onPivot && resolvedIps.length + relatedDomains.length > GRAPH_HOST_LIMIT && (
        <details className="group">
          <summary className="cursor-pointer text-xs text-accent-fg hover:underline list-none">
            All {resolvedIps.length + relatedDomains.length} related hosts
          </summary>
          <div className="mt-2 space-y-2">
            {resolvedIps.length > 0 && <PivotSection items={resolvedIps} label="Resolved IPs — click to investigate" color="blue" onPivot={onPivot} />}
            {relatedDomains.length > 0 && <PivotSection items={relatedDomains} label="Certificate SANs — click to investigate" color="purple" onPivot={onPivot} />}
          </div>
        </details>
      )}

      <AttackPanel hits={techniques} onHunt={onHunt} />

      <ProviderMatrix results={results} />

      <ProviderComparisonPanel results={results} iocType={response.ioc.type} />

      <p className="text-[11px] font-mono text-fg-4">Analysed {new Date(analysedAt).toLocaleString()}</p>
    </div>
  );
}
