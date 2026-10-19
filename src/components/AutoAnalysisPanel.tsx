import { useState, useCallback, useEffect, useLayoutEffect, useRef } from 'react';
import type { DetectedIoc } from '../types/ioc';
import type { AnalysisResponse, EmailHeaderAnalysisResponse } from '../types/analysis';
import { streamAutoAnalysis, runEmailHeaderAnalysis } from '../lib/apiClient';
import type { AnalysisProgress } from '../lib/apiClient';
import { AnalysisResultView } from './AnalysisResultView';
import { EmailAnalysisView } from './EmailAnalysisView';
import { ElapsedTimer, LiveProgress } from './AnalysisProgress';

type AnyResult = AnalysisResponse | EmailHeaderAnalysisResponse;

/** A request from the parent to run analysis; a new id means a new run. */
export interface RunRequest {
  id: number;
  forceRefresh: boolean;
}

interface AutoAnalysisPanelProps {
  ioc: DetectedIoc | null;
  workflowId: string | null;
  onComplete?: (response: AnalysisResponse | null) => void;
  onPivot?: (iocValue: string) => void;
  preloadResult?: AnalysisResponse | null;
  onLoadingChange?: (loading: boolean) => void;
  /** Pending run, handled once and then acknowledged via onRunHandled */
  runRequest?: RunRequest | null;
  onRunHandled?: () => void;
  workflow?: { id: string; name: string } | null;
  onHunt?: (techniqueIds: string[]) => void;
}

// ── Main ──────────────────────────────────────────────────────────────────

export function AutoAnalysisPanel({ ioc, workflowId, onComplete, onPivot, preloadResult, onLoadingChange, runRequest, onRunHandled, workflow, onHunt }: AutoAnalysisPanelProps) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnyResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<AnalysisProgress>({ providers: [], results: [] });
  const [includeHunter, setIncludeHunter] = useState(false);
  // Tracks the active run; a new Symbol per run means only the latest run can commit results.
  const activeRunIdRef = useRef<symbol | null>(null);
  // Keep onLoadingChange stable in effects without adding it to deps.
  const onLoadingChangeRef = useRef(onLoadingChange);
  useEffect(() => { onLoadingChangeRef.current = onLoadingChange; });

  const isEmailHeader = ioc?.isEmailHeader === true;
  const isEmailHeaderWorkflow = workflowId === 'email-header-review';
  const disabled = !ioc || !ioc.trimmed || (ioc.type === 'unknown' && !isEmailHeader && !isEmailHeaderWorkflow);
  const hunterApplicable = ioc?.type === 'domain' || ioc?.type === 'url' || ioc?.type === 'email';
  const hunterLabel = ioc?.type === 'email'
    ? 'email verify + person enrichment (uses 2 credits)'
    : 'company profile & email intel (uses 1 credit)';

  // Reset state when the IOC changes. useLayoutEffect fires synchronously before paint so this
  // always completes before the user can interact. Setting activeRunIdRef to null cancels any
  // in-flight run for the previous IOC without touching the gen counter.
  useLayoutEffect(() => {
    activeRunIdRef.current = null;
    setLoading(false);
    setResult(null);
    setError(null);
    onLoadingChangeRef.current?.(false);
  }, [ioc?.normalised]);

  // Workflow changes don't clear results: /api/analyse selects providers by IOC type and
  // only uses the workflow as prompt context, so existing results remain valid.

  // Restore a previously-saved result when loaded from history.
  // Declared after the reset effect so it fires second and wins.
  useEffect(() => {
    if (!preloadResult) return;
    setResult(preloadResult);
    setError(null);
    setLoading(false);
    onLoadingChangeRef.current?.(false);
  }, [preloadResult]);

  const handleRun = useCallback(async (forceRefresh = false) => {
    if (!ioc || disabled) return;
    const snap = ioc;
    const id = Symbol();
    activeRunIdRef.current = id;
    setLoading(true); setError(null); setResult(null);
    onLoadingChangeRef.current?.(true);
    try {
      if (snap.isEmailHeader || isEmailHeaderWorkflow) {
        const r = await runEmailHeaderAnalysis({
          rawHeaders: snap.original,
          options: { forceRefresh },
        });
        if (activeRunIdRef.current !== id) return;
        if (!r) setError('Analysis failed — check the backend is running.');
        else setResult(r);
      } else {
        setProgress({ providers: [], results: [] });
        const r = await streamAutoAnalysis({
          ioc: { original: snap.original, normalised: snap.normalised, type: snap.type },
          workflowId: workflowId ?? undefined,
          options: { forceRefresh, includeHunter },
        }, p => { if (activeRunIdRef.current === id) setProgress(p); });
        if (activeRunIdRef.current !== id) return;
        if (!r) { setError('Analysis failed — check the backend is running.'); }
        else { setResult(r); onComplete?.(r); }
      }
    } catch (err) {
      if (activeRunIdRef.current !== id) return;
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      if (activeRunIdRef.current === id) {
        setLoading(false);
        onLoadingChangeRef.current?.(false);
      }
    }
  }, [ioc, workflowId, disabled, onComplete, includeHunter, isEmailHeaderWorkflow]);

  // Run when the parent asks. This effect fires after the layout effect above has reset
  // state for a new indicator, so a pivot to a new IOC runs against that IOC. The request
  // is acknowledged at once so a later remount (switching pages) doesn't run it again.
  // The handled id also guards StrictMode's double effect invocation in development.
  const handledRunIdRef = useRef<number | null>(null);
  useEffect(() => {
    if (!runRequest || runRequest.id === handledRunIdRef.current) return;
    handledRunIdRef.current = runRequest.id;
    onRunHandled?.();
    void handleRun(runRequest.forceRefresh);
  }, [runRequest, handleRun, onRunHandled]);

  // Discriminate the two result shapes
  const emailResult = result && 'parsed' in result ? result as EmailHeaderAnalysisResponse : null;
  const iocResult   = result && 'ioc' in result   ? result as AnalysisResponse             : null;

  // In bar-driven mode, don't render the card at all until there is something to show.
  // Nothing to show until a run starts (the AnalysisBar owns the Run button)
  if (!loading && !result && !error) return null;

  return (
    <div className="wb-card overflow-hidden">
      {/* Hunter toggle — only for domain/url IOCs */}
      {hunterApplicable && (
        <div className="flex items-center justify-between px-5 py-2.5 border-b border-line-soft bg-inset">
          <div className="flex items-center gap-2">
            <svg className="w-3.5 h-3.5 text-fg-4 shrink-0" fill="none" stroke="currentColor" strokeWidth={1.8} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35M17 11A6 6 0 1 1 5 11a6 6 0 0 1 12 0z" />
            </svg>
            <span className="text-xs font-medium text-fg-2">Include Hunter.io</span>
            <span className="text-[11px] text-fg-4">— {hunterLabel}</span>
          </div>
          <button
            role="switch"
            aria-checked={includeHunter}
            onClick={() => setIncludeHunter(v => !v)}
            disabled={loading}
            className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 focus:outline-none disabled:opacity-40 disabled:cursor-not-allowed ${
              includeHunter ? 'bg-accent' : 'bg-line-strong'
            }`}
          >
            <span className={`pointer-events-none inline-block h-4 w-4 rounded-full bg-surface shadow-sm ring-0 transition-transform duration-200 ${
              includeHunter ? 'translate-x-4' : 'translate-x-0'
            }`} />
          </button>
        </div>
      )}

      {/* Body */}
      <div className="p-5">
        {loading && ((isEmailHeader || isEmailHeaderWorkflow)
          ? <ElapsedTimer running isEmail />
          : <LiveProgress progress={progress} />)}

        {error && !loading && (
          <div className="flex gap-2.5 p-3 rounded-lg bg-danger-bg border border-danger-line text-xs text-danger-fg">
            <svg className="w-4 h-4 shrink-0 mt-0.5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
              <circle cx="12" cy="12" r="10" /><path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4m0 4h.01" />
            </svg>
            {error}
          </div>
        )}

        {emailResult && !loading && <EmailAnalysisView result={emailResult} iocType={ioc?.type} />}

        {/* Standard IOC result */}
        {iocResult && !loading && <AnalysisResultView response={iocResult} onPivot={onPivot} workflow={workflow} onHunt={onHunt} />}
      </div>
    </div>
  );
}
