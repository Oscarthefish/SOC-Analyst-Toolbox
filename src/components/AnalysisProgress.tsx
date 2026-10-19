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

const SEV_DOT: Record<string, string> = {
  critical: 'bg-danger', high: 'bg-danger', medium: 'bg-warn', low: 'bg-accent', benign: 'bg-ok', unknown: 'bg-fg-4',
};
const SEV_TEXT: Record<string, string> = {
  critical: 'text-danger-fg', high: 'text-danger-fg', medium: 'text-warn-fg', low: 'text-accent-fg', benign: 'text-ok-fg', unknown: 'text-fg-2',
};

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

  return (
    <div className="space-y-4" aria-live="polite">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <span className="w-4 h-4 rounded-full border-2 border-line border-t-accent animate-spin" />
          <p className="text-[13px] font-medium text-fg-1">
            {total === 0 ? 'Starting analysis…'
              : !overall ? `Querying providers · ${doneCount}/${total}`
              : 'Writing summary with local LLM…'}
          </p>
        </div>
        <span className="text-xs font-mono text-fg-4 tabular-nums">{elapsed}s</span>
      </div>

      {overall && (
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-3 py-2.5 rounded-md border border-line bg-inset">
          <span className="text-[11px] text-fg-4">Verdict</span>
          <span className={`text-[13px] font-semibold capitalize ${SEV_TEXT[overall.severity] ?? 'text-fg-1'}`}>{overall.severity}</span>
          <span className="text-xs text-fg-3">{overall.confidence} confidence</span>
          <span className="text-xs text-fg-4">· the written summary will follow</span>
        </div>
      )}

      {total > 0 && (
        <div className="grid gap-x-4 gap-y-1 grid-cols-[repeat(auto-fill,minmax(180px,1fr))]">
          {progress.providers.map(id => {
            const r = byId.get(id);
            const ok = r && (r.status === 'ok' || r.status === 'cached');
            return (
              <div key={id} className="flex items-center gap-2 text-xs min-w-0" title={r?.summary}>
                <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                  !r ? 'bg-line-strong animate-pulse' : ok ? SEV_DOT[r.severity] ?? 'bg-fg-4' : 'bg-transparent border border-fg-4'
                }`} />
                <span className={`truncate ${r ? 'text-fg-2' : 'text-fg-4'}`}>{r?.providerName ?? id}</span>
                <span className="ml-auto text-[11px] text-fg-4 shrink-0">
                  {!r ? '' : ok ? (r.status === 'cached' ? 'cached' : r.severity) : r.status.replace('_', ' ')}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
