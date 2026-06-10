import { useState, useCallback, useRef } from 'react';
import { detectIoc } from '../lib/detectIoc';
import { runEnrichment } from '../lib/apiClient';
import type { IocType } from '../types/ioc';
import type { Severity, EnrichmentResult } from '../types/enrichment';

interface BatchTriagePanelProps {
  onInvestigate: (ioc: string) => void;
}

type RowStatus = 'pending' | 'running' | 'done' | 'error' | 'skipped';

interface BatchRow {
  id: string;
  raw: string;
  normalised: string;
  type: IocType | 'unknown';
  status: RowStatus;
  severity?: Severity;
  confidence?: string;
  topFinding?: string;
  errorMsg?: string;
}

const TYPE_LABELS: Record<string, string> = {
  ipv4: 'IPv4', ipv6: 'IPv6', domain: 'Domain', url: 'URL',
  md5: 'MD5', sha1: 'SHA-1', sha256: 'SHA-256', email: 'Email',
  asn: 'ASN', cidr: 'CIDR', cve: 'CVE', unknown: '?',
};

const SEV_CLS: Record<Severity, string> = {
  critical: 'bg-[#fef3f2] border-[#fecdca] text-[#b42318]',
  high:     'bg-[#fef3f2] border-[#fecdca] text-[#b42318]',
  medium:   'bg-[#fffaeb] border-[#fedf89] text-[#b54708]',
  low:      'bg-[#eff8ff] border-[#b2ddff] text-[#175cd3]',
  benign:   'bg-[#ecfdf3] border-[#abefc6] text-[#067647]',
  unknown:  'bg-[#f2f4f7] border-[#e4e7ec] text-[#667085]',
};

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, benign: 4, unknown: 5,
};

function extractTopFinding(results: EnrichmentResult[]): string {
  const active = results
    .filter(r => r.status === 'ok' || r.status === 'cached')
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));
  const best = active[0];
  if (!best) return 'No data returned.';
  const kf = best.keyFacts?.[0];
  if (kf) return `[${best.providerName}] ${kf.label}: ${kf.value}`;
  const s = best.summary;
  return s.length > 110 ? s.slice(0, 107) + '…' : s;
}

function parseInput(raw: string): BatchRow[] {
  const lines = raw
    .split(/[\n,]+/)
    .map(l => l.trim())
    .filter(Boolean);
  const seen = new Set<string>();
  const rows: BatchRow[] = [];
  for (const line of lines.slice(0, 50)) {
    const detected = detectIoc(line);
    const key = detected.normalised || line;
    if (seen.has(key)) continue;
    seen.add(key);
    rows.push({
      id: key,
      raw: line,
      normalised: detected.normalised || line,
      type: detected.type,
      status: detected.type === 'unknown' || detected.isEmailHeader ? 'skipped' : 'pending',
    });
  }
  return rows;
}

export function BatchTriagePanel({ onInvestigate }: BatchTriagePanelProps) {
  const [input, setInput] = useState('');
  const [rows, setRows] = useState<BatchRow[]>([]);
  const [running, setRunning] = useState(false);
  const abortRef = useRef(false);

  const updateRow = useCallback((id: string, update: Partial<BatchRow>) => {
    setRows(prev => prev.map(r => r.id === id ? { ...r, ...update } : r));
  }, []);

  const handleParse = useCallback(() => {
    if (!input.trim()) return;
    setRows(parseInput(input));
  }, [input]);

  const handleRun = useCallback(async () => {
    if (running) return;
    abortRef.current = false;
    setRunning(true);

    const pending = rows.filter(r => r.status === 'pending');
    const CONCURRENCY = 5;
    let idx = 0;

    async function worker() {
      while (idx < pending.length && !abortRef.current) {
        const row = pending[idx++]!;
        updateRow(row.id, { status: 'running' });
        try {
          const result = await runEnrichment({
            ioc: { original: row.raw, normalised: row.normalised, type: row.type as IocType },
          });
          if (!result) {
            updateRow(row.id, { status: 'error', errorMsg: 'Backend unreachable' });
          } else {
            updateRow(row.id, {
              status: 'done',
              severity: result.overall.severity,
              confidence: result.overall.confidence,
              topFinding: extractTopFinding(result.results),
            });
          }
        } catch (err) {
          updateRow(row.id, {
            status: 'error',
            errorMsg: err instanceof Error ? err.message : 'Failed',
          });
        }
      }
    }

    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, pending.length) }, worker));
    setRunning(false);
  }, [rows, running, updateRow]);

  const handleClear = useCallback(() => {
    setInput(''); setRows([]); abortRef.current = true;
  }, []);

  const done = rows.filter(r => r.status === 'done' || r.status === 'error').length;
  const runnable = rows.filter(r => r.status === 'pending' || r.status === 'running').length;
  const total = rows.filter(r => r.status !== 'skipped').length;

  return (
    <div className="space-y-4">
      <div className="wb-card p-5 space-y-4">
        <div>
          <p className="wb-label mb-1">Batch IOC Triage</p>
          <p className="text-xs text-[#98a2b3]">Paste up to 50 IOCs — one per line or comma-separated. Mixed types supported.</p>
        </div>

        <textarea
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) void handleRun(); }}
          placeholder={'185.220.101.42\nevil-phishing.com\ne3b0c44298fc1c149afbf4c8996fb924...\nCVE-2024-1234'}
          className="w-full h-32 px-3 py-2.5 text-xs font-mono rounded-lg border border-[#e4e7ec] bg-[#fafbfc] placeholder-[#d0d5dd] text-[#101828] resize-none focus:outline-none focus:border-[#84caff] focus:bg-white transition-colors"
          disabled={running}
        />

        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={handleParse}
            disabled={!input.trim() || running}
            className="px-3.5 py-2 text-xs font-semibold rounded-lg border border-[#e4e7ec] bg-white text-[#344054] hover:bg-[#f9fafb] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            Parse IOCs
          </button>
          <button
            onClick={() => void handleRun()}
            disabled={running || rows.filter(r => r.status === 'pending').length === 0}
            className="px-3.5 py-2 text-xs font-semibold rounded-lg bg-[#1570ef] text-white hover:bg-[#175cd3] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            {running ? `Running… ${done}/${total}` : `Run Triage (${rows.filter(r => r.status === 'pending').length})`}
          </button>
          {rows.length > 0 && (
            <button
              onClick={handleClear}
              className="px-3 py-2 text-xs font-medium rounded-lg border border-[#e4e7ec] bg-white text-[#667085] hover:text-[#344054] transition-colors"
            >
              Clear
            </button>
          )}
          {running && (
            <div className="flex items-center gap-1.5 text-xs text-[#667085]">
              <div className="w-3 h-3 rounded-full border-2 border-[#e4e7ec] border-t-[#1570ef] animate-spin" />
              {total - done} remaining
            </div>
          )}
        </div>
      </div>

      {rows.length > 0 && (
        <div className="wb-card overflow-hidden">
          <div className="px-5 py-3 border-b border-[#f2f4f7] flex items-center justify-between">
            <p className="wb-label">
              Results
              <span className="ml-2 font-normal text-[#98a2b3]">
                {rows.length} IOC{rows.length !== 1 ? 's' : ''}
                {rows.some(r => r.status === 'skipped') ? ` · ${rows.filter(r => r.status === 'skipped').length} skipped (unknown type)` : ''}
              </span>
            </p>
            {!running && done > 0 && (
              <div className="flex gap-3 text-xs text-[#667085]">
                {(['critical', 'high', 'medium'] as Severity[]).map(s => {
                  const n = rows.filter(r => r.severity === s).length;
                  return n > 0 ? (
                    <span key={s} className={`px-2 py-0.5 rounded border text-[11px] font-semibold ${SEV_CLS[s]}`}>
                      {n} {s}
                    </span>
                  ) : null;
                })}
              </div>
            )}
          </div>

          <div className="divide-y divide-[#f2f4f7]">
            {rows.map(row => (
              <div
                key={row.id}
                className={`flex items-start gap-3 px-5 py-3 transition-colors ${
                  row.status === 'running' ? 'bg-[#f9fafb]' : ''
                } ${row.status === 'skipped' ? 'opacity-40' : ''}`}
              >
                {/* Status indicator */}
                <div className="mt-0.5 shrink-0">
                  {row.status === 'running' && (
                    <div className="w-3.5 h-3.5 rounded-full border-2 border-[#e4e7ec] border-t-[#1570ef] animate-spin" />
                  )}
                  {row.status === 'pending' && (
                    <div className="w-3.5 h-3.5 rounded-full border border-[#d0d5dd] bg-white" />
                  )}
                  {row.status === 'done' && row.severity && (
                    <div className={`w-3.5 h-3.5 rounded-full border ${
                      row.severity === 'critical' || row.severity === 'high' ? 'bg-[#d92d20] border-[#d92d20]'
                      : row.severity === 'medium' ? 'bg-[#dc6803] border-[#dc6803]'
                      : row.severity === 'low' ? 'bg-[#1570ef] border-[#1570ef]'
                      : row.severity === 'benign' ? 'bg-[#079455] border-[#079455]'
                      : 'bg-[#98a2b3] border-[#98a2b3]'
                    }`} />
                  )}
                  {row.status === 'error' && (
                    <div className="w-3.5 h-3.5 rounded-full bg-[#d92d20] border-[#d92d20]" />
                  )}
                  {row.status === 'skipped' && (
                    <div className="w-3.5 h-3.5 rounded-full border border-[#d0d5dd] bg-[#f2f4f7]" />
                  )}
                </div>

                {/* IOC value */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <code className="text-[12px] font-mono text-[#101828] break-all leading-snug">
                      {row.normalised.length > 60 ? row.normalised.slice(0, 57) + '…' : row.normalised}
                    </code>
                    <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-[#f2f4f7] text-[#667085] shrink-0">
                      {TYPE_LABELS[row.type] ?? row.type.toUpperCase()}
                    </span>
                    {row.status === 'done' && row.severity && (
                      <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${SEV_CLS[row.severity]} shrink-0`}>
                        {row.severity}
                      </span>
                    )}
                  </div>
                  {row.topFinding && (
                    <p className="text-[11px] text-[#475467] mt-0.5 leading-snug">{row.topFinding}</p>
                  )}
                  {row.errorMsg && (
                    <p className="text-[11px] text-[#b42318] mt-0.5">{row.errorMsg}</p>
                  )}
                  {row.status === 'skipped' && (
                    <p className="text-[11px] text-[#98a2b3] mt-0.5">Type not recognised — skipped</p>
                  )}
                </div>

                {/* Pivot button */}
                {(row.status === 'done' || row.status === 'pending') && row.type !== 'unknown' && (
                  <button
                    onClick={() => onInvestigate(row.normalised)}
                    className="shrink-0 flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-[#e4e7ec] bg-white text-[#475467] text-xs font-medium hover:border-[#b2ddff] hover:text-[#1570ef] transition-colors"
                    title="Open in Single IOC tab"
                  >
                    Triage
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5 12h14M12 5l7 7-7 7" />
                    </svg>
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
