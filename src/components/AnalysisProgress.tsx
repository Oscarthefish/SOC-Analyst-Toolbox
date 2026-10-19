import { useState, useEffect, useRef } from 'react';
import type { AnalysisProgress } from '../lib/apiClient';

// ── Elapsed timer ─────────────────────────────────────────────────────────

export function ElapsedTimer({ running, isEmail }: { running: boolean; isEmail?: boolean }) {
  const [e, setE] = useState(0);
  const ref = useRef<ReturnType<typeof setInterval> | null>(null);
  useEffect(() => {
    if (running) {
      setE(0);
      ref.current = setInterval(() => setE(x => x + 1), 1000);
    } else {
      if (ref.current) { clearInterval(ref.current); ref.current = null; }
    }
    return () => { if (ref.current) clearInterval(ref.current); };
  }, [running]);
  if (!running) return null;
  const stage = isEmail
    ? (e < 10 ? 'Parsing email headers…'
      : e < 30 ? 'Enriching sending IP and domain…'
      : e < 55 ? 'Generating analyst narrative…'
      : 'Waiting for Ollama…')
    : (e < 15 ? 'Querying enrichment providers…'
      : e < 40 ? 'Aggregating provider results…'
      : e < 60 ? 'Generating analyst narrative…'
      : 'Waiting for Ollama…');
  const pct = Math.min(95, e < 15 ? (e / 15) * 40 : e < 40 ? 40 + ((e - 15) / 25) * 30 : 70 + ((e - 40) / 30) * 25);
  return (
    <div className="py-8 px-4 space-y-4 text-center">
      <div className="w-10 h-10 rounded-full border-2 border-line border-t-accent animate-spin mx-auto" />
      <div>
        <p className="text-sm font-medium text-fg-1">{stage}</p>
        <p className="text-xs font-mono text-fg-4 mt-0.5">{e}s elapsed</p>
      </div>
      <div className="w-full bg-raised rounded-full h-1.5 max-w-[200px] mx-auto">
        <div className="bg-accent h-1.5 rounded-full transition-all duration-1000" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

// ── Live progress (streamed analysis) ──────────────────────────────────────

const TILE: Record<string, string> = {
  critical: 'border-danger-line bg-danger-bg', high: 'border-high-line bg-high-bg', medium: 'border-warn-line bg-warn-bg',
  low: 'border-line bg-c1-bg', benign: 'border-ok-line bg-ok-bg', unknown: 'border-line bg-surface',
};
const RULE: Record<string, string> = {
  critical: 'bg-danger', high: 'bg-high', medium: 'bg-warn', low: 'bg-c1', benign: 'bg-ok', unknown: 'bg-line-strong',
};
const SEV_TEXT: Record<string, string> = {
  critical: 'text-danger-fg', high: 'text-high-fg', medium: 'text-warn-fg', low: 'text-c1-fg', benign: 'text-ok-fg', unknown: 'text-fg-2',
};

type StepState = 'done' | 'current' | 'pending';

function Step({ state, title, detail, last }: { state: StepState; title: string; detail?: string; last?: boolean }) {
  return (
    <li className="flex-1 min-w-0 flex items-start gap-2.5" aria-current={state === 'current' ? 'step' : undefined}>
      <span className={`mt-px w-6 h-6 rounded-full grid place-items-center shrink-0 border-2 ${
        state === 'done' ? 'bg-ok border-ok text-white'
          : state === 'current' ? 'border-accent bg-accent-bg'
          : 'border-line-strong bg-surface'
      }`}>
        {state === 'done' && (
          <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={3} strokeLinecap="round" strokeLinejoin="round"><path d="M5 12l5 5 9-10" /></svg>
        )}
        {state === 'current' && <span className="w-2 h-2 rounded-full bg-accent animate-pulse" />}
      </span>
      <span className="min-w-0 flex-1">
        <span className={`block text-[13px] ${state === 'pending' ? 'text-fg-4' : 'text-fg-1 font-medium'}`}>{title}</span>
        {detail && <span className="block text-[11px] text-fg-3 truncate">{detail}</span>}
      </span>
      {!last && <span className={`hidden sm:block mt-3 h-[2px] flex-1 max-w-16 rounded ${state === 'done' ? 'bg-ok' : 'bg-line'}`} aria-hidden />}
    </li>
  );
}

export function LiveProgress({ progress }: { progress: AnalysisProgress }) {
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setElapsed(x => x + 1), 1000);
    return () => clearInterval(t);
  }, []);

  const byId = new Map(progress.results.map(r => [r.providerId, r]));
  const total = progress.providers.length;
  const doneCount = progress.results.length;
  const overall = progress.overall;

  const queryState: StepState = total === 0 ? 'pending' : overall ? 'done' : 'current';
  const scoreState: StepState = overall ? 'done' : 'pending';
  const summaryState: StepState = overall ? 'current' : 'pending';

  return (
    <div className="space-y-4" aria-live="polite">
      <div className="flex items-start gap-4">
        <ol className="flex-1 flex flex-col sm:flex-row gap-3 sm:gap-4">
          <Step state={total === 0 ? 'current' : 'done'} title="Plan" detail={total ? `${total} sources apply` : 'Choosing sources…'} />
          <Step state={queryState} title="Query sources" detail={total ? `${doneCount} of ${total} answered` : undefined} />
          <Step
            state={scoreState}
            title="Score"
            detail={overall ? `${overall.severity[0]!.toUpperCase()}${overall.severity.slice(1)} · ${overall.confidence} confidence` : undefined}
          />
          <Step state={summaryState} title="Written summary" detail={overall ? 'Local LLM is writing…' : undefined} last />
        </ol>
        <span className="text-xs font-mono text-fg-4 tabular-nums shrink-0">{elapsed}s</span>
      </div>

      {total > 0 && (
        <div className="h-1.5 rounded-full bg-raised overflow-hidden">
          <div className="h-full bg-accent rounded-full transition-[width] duration-300" style={{ width: `${(doneCount / total) * 100}%` }} />
        </div>
      )}

      {total > 0 && (
        <div className="grid gap-1.5 grid-cols-[repeat(auto-fill,minmax(150px,1fr))]">
          {progress.providers.map(id => {
            const r = byId.get(id);
            const ok = r && (r.status === 'ok' || r.status === 'cached');
            const sev = ok ? r.severity : null;
            return (
              <div
                key={id}
                title={r?.summary}
                className={`relative rounded-md border pl-3 pr-2 py-1.5 overflow-hidden text-xs transition-colors ${
                  !r ? 'border-line-soft bg-inset' : sev ? TILE[sev] ?? TILE.unknown : 'border-line-soft border-dashed bg-inset'
                }`}
              >
                <span className={`absolute left-0 top-0 bottom-0 w-[3px] ${!r ? 'bg-line animate-pulse' : sev ? RULE[sev] ?? RULE.unknown : 'bg-transparent'}`} aria-hidden />
                <span className={`block truncate ${r ? 'text-fg-1 font-medium' : 'text-fg-4'}`}>{r?.providerName ?? id}</span>
                <span className={`block text-[11px] truncate capitalize ${sev ? SEV_TEXT[sev] : 'text-fg-4'}`}>
                  {!r ? 'Waiting…' : ok ? (sev === 'unknown' ? 'Context only' : sev) : r.status.replace('_', ' ')}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
