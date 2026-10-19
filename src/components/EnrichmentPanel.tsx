import { useState, useCallback } from 'react';
import type { DetectedIoc } from '../types/ioc';
import type { EnrichmentResponse, HealthResponse, ContradictionFlag } from '../types/enrichment';
import { runEnrichment } from '../lib/apiClient';
import { ProviderStatus } from './ProviderStatus';
import { EnrichmentCard } from './EnrichmentCard';
import { KeyFactsSummaryStrip, PivotSection, ContradictionBanner } from './enrichmentShared';

interface EnrichmentPanelProps {
  ioc: DetectedIoc | null;
  workflowId: string | null;
  isSensitiveUrl: boolean;
  onEnrichmentComplete?: (response: EnrichmentResponse | null) => void;
  contradictions?: ContradictionFlag[];
  onPivot?: (iocValue: string) => void;
}

export function EnrichmentPanel({ ioc, workflowId, isSensitiveUrl, onEnrichmentComplete, contradictions, onPivot }: EnrichmentPanelProps) {
  const [backendHealth, setBackendHealth] = useState<HealthResponse | null>(null);
  const [enrichmentResponse, setEnrichmentResponse] = useState<EnrichmentResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [allowSensitiveUrl, setAllowSensitiveUrl] = useState(false);

  const handleHealthChange = useCallback((health: HealthResponse | null) => {
    setBackendHealth(health);
  }, []);

  const handleRun = useCallback(async (forceRefresh = false) => {
    if (!ioc || ioc.type === 'unknown') return;
    setLoading(true);
    setError(null);
    try {
      const result = await runEnrichment({
        ioc: { original: ioc.original, normalised: ioc.normalised, type: ioc.type },
        workflowId: workflowId ?? undefined,
        options: { forceRefresh, allowSensitiveUrl },
      });
      setEnrichmentResponse(result);
      onEnrichmentComplete?.(result);
      if (!result) setError('Enrichment request failed. Check the backend is running.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
      setEnrichmentResponse(null);
      onEnrichmentComplete?.(null);
    } finally {
      setLoading(false);
    }
  }, [ioc, workflowId, allowSensitiveUrl, onEnrichmentComplete]);

  const canRun = backendHealth !== null && ioc && ioc.type !== 'unknown' && !ioc.isEmailHeader;

  const sev = enrichmentResponse?.overall.severity;
  const sevCls = sev === 'critical' || sev === 'high' ? 'bg-danger-bg border-danger-line text-danger-fg'
    : sev === 'medium' ? 'bg-warn-bg border-warn-line text-warn-fg'
    : sev === 'low' ? 'bg-accent-bg border-accent-line text-accent-fg'
    : sev === 'benign' ? 'bg-ok-bg border-ok-line text-ok-fg'
    : 'bg-raised border-line text-fg-2';

  return (
    <div className="wb-card p-5 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <p className="wb-label">API Enrichment</p>
          <p className="text-xs text-fg-4 mt-0.5">Direct provider lookups via local backend</p>
        </div>
      </div>

      <ProviderStatus onHealthChange={handleHealthChange} />

      {backendHealth === null && (
        <p className="text-xs text-fg-4">Start the enrichment backend to enable automated API lookups.</p>
      )}

      {backendHealth !== null && (!ioc || ioc.type === 'unknown') && (
        <p className="text-xs text-fg-4">Enter a valid IOC to run enrichment.</p>
      )}

      {canRun && (
        <div className="space-y-3">
          <div className="text-xs text-fg-3 bg-inset border border-line rounded-lg p-3 space-y-1">
            <p><strong className="text-fg-2">VirusTotal:</strong> Lookup only — no file upload or URL submission.</p>
            <p><strong className="text-fg-2">urlscan.io:</strong> Search only — existing scans queried, no new submissions.</p>
            {isSensitiveUrl && (
              <p className="text-warn-fg"><strong>Sensitive URL detected.</strong> Enable override below only if comfortable sending this URL to third-party APIs.</p>
            )}
          </div>

          {isSensitiveUrl && (
            <label className="flex items-center gap-2 text-xs text-fg-2 cursor-pointer">
              <input type="checkbox" checked={allowSensitiveUrl} onChange={e => setAllowSensitiveUrl(e.target.checked)}
                className="rounded border-line-strong" />
              Allow sensitive URL lookups
            </label>
          )}

          <div className="flex flex-wrap gap-2">
            <button onClick={() => void handleRun(false)} disabled={loading}
              className="px-3.5 py-2 text-xs font-semibold rounded-lg bg-accent text-white hover:bg-accent-strong transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
              {loading ? 'Running…' : 'Run Enrichment'}
            </button>
            {enrichmentResponse && (
              <button onClick={() => void handleRun(true)} disabled={loading}
                className="px-3 py-2 text-xs font-medium rounded-lg border border-line bg-surface text-fg-2 hover:border-line-strong transition-colors disabled:opacity-50">
                Refresh (bypass cache)
              </button>
            )}
          </div>

          {loading && (
            <div className="flex items-center gap-2 text-xs text-fg-3">
              <div className="w-4 h-4 rounded-full border-2 border-line border-t-accent animate-spin shrink-0" />
              Querying enrichment providers…
            </div>
          )}

          {error && (
            <div className="text-xs text-danger-fg bg-danger-bg border border-danger-line rounded-lg p-3">{error}</div>
          )}

          {enrichmentResponse && !loading && (
            <div className="space-y-3">
              <div className={`rounded-lg border px-4 py-3 ${sevCls}`}>
                <div className="flex flex-wrap items-center gap-2 mb-1">
                  <span className="text-[11px] font-bold uppercase tracking-wider opacity-60">Overall Assessment</span>
                  <span className="font-semibold capitalize">{enrichmentResponse.overall.severity}</span>
                  <span className="opacity-60 text-[11px]">· confidence {enrichmentResponse.overall.confidence}</span>
                </div>
                <p className="text-xs opacity-80">{enrichmentResponse.overall.summary}</p>
                {enrichmentResponse.overall.recommendedActions.length > 0 && (
                  <ul className="mt-2 space-y-0.5 text-xs opacity-80">
                    {enrichmentResponse.overall.recommendedActions.map((a, i) => (
                      <li key={i} className="flex gap-1.5"><span className="opacity-50">·</span>{a}</li>
                    ))}
                  </ul>
                )}
              </div>

              <KeyFactsSummaryStrip results={enrichmentResponse.results} />

              {onPivot && (
                <PivotSection
                  items={enrichmentResponse.results
                    .filter(r => r.status === 'ok' || r.status === 'cached')
                    .flatMap(r => r.resolvedIps ?? [])}
                  label="Resolved IPs — pivot to IP triage"
                  color="blue"
                  onPivot={onPivot}
                />
              )}

              {onPivot && (
                <PivotSection
                  items={enrichmentResponse.results
                    .filter(r => r.status === 'ok' || r.status === 'cached')
                    .flatMap(r => r.relatedDomains ?? [])}
                  label="Certificate SANs — pivot to domain triage"
                  color="purple"
                  onPivot={onPivot}
                />
              )}

              {(contradictions?.length ?? 0) > 0 && (
                <ContradictionBanner contradictions={contradictions!} />
              )}

              <div className="space-y-1.5">
                <p className="wb-label">Provider Results ({enrichmentResponse.results.length})</p>
                {enrichmentResponse.results.map(result => (
                  <EnrichmentCard key={result.providerId} result={result} />
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
