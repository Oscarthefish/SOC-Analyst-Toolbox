import { useState, useCallback, useEffect, useRef } from 'react';
import type { DetectedIoc } from '../types/ioc';
import type { AnalysisResponse, EmailHeaderAnalysisResponse, ParsedEmailHeaders } from '../types/analysis';
import type { EnrichmentResult } from '../types/enrichment';
import { runAutoAnalysis, runEmailHeaderAnalysis } from '../lib/apiClient';

interface AutoAnalysisPanelProps {
  ioc: DetectedIoc | null;
  workflowId: string | null;
  onComplete?: (response: AnalysisResponse | null) => void;
  onPivot?: (iocValue: string) => void;
  autoRun?: boolean;
  onAutoRunConsumed?: () => void;
}

// ── Narrative parser ──────────────────────────────────────────────────────

interface ParsedNarrative {
  verdict: string | null;
  findings: string[];
  actions: string[];
  notes: string | null;
}

function parseBullets(block: string): string[] {
  return block
    .split('\n')
    .map(l => l.replace(/^[\s]*[-•*]\s+/, '').replace(/^\d+\.\s+/, '').trim())
    .filter(Boolean);
}

function parseNarrative(text: string): ParsedNarrative {
  const t = text.trim();
  const verdictMatch = t.match(/VERDICT:\s*(.+)/i);
  const verdict = verdictMatch ? verdictMatch[1].replace(/\*+/g, '').trim() : null;

  function extractSection(name: string): string {
    const re = new RegExp(`${name}:\\s*\\n([\\s\\S]*?)(?=\\n[A-Z ]{3,}:|$)`, 'i');
    const m = t.match(re);
    return m ? m[1].trim() : '';
  }

  const findings = parseBullets(extractSection('KEY FINDINGS'));
  const actions  = parseBullets(extractSection('RECOMMENDED ACTIONS'));
  const notesRaw = extractSection('ANALYST NOTES');
  const notes    = notesRaw.replace(/^[-•*]\s+/gm, '').trim() || null;

  return { verdict, findings, actions, notes };
}

// ── Verdict styling ───────────────────────────────────────────────────────

interface VStyle { bar: string; text: string; dot: string; meter: string; }

const VSTYLES: Record<string, VStyle> = {
  'benign':            { bar: 'bg-[#ecfdf3] border-[#abefc6]', text: 'text-[#067647]', dot: 'bg-[#079455]', meter: 'bg-[#079455]' },
  'low risk':          { bar: 'bg-[#eff8ff] border-[#b2ddff]', text: 'text-[#175cd3]', dot: 'bg-[#1570ef]', meter: 'bg-[#1570ef]' },
  'suspicious':        { bar: 'bg-[#fffaeb] border-[#fedf89]', text: 'text-[#b54708]', dot: 'bg-[#dc6803]', meter: 'bg-[#dc6803]' },
  'likely malicious':  { bar: 'bg-[#fff6ed] border-[#fddcab]', text: 'text-[#c4320a]', dot: 'bg-[#ef6820]', meter: 'bg-[#ef6820]' },
  'malicious':         { bar: 'bg-[#fef3f2] border-[#fecdca]', text: 'text-[#b42318]', dot: 'bg-[#d92d20]', meter: 'bg-[#d92d20]' },
  'insufficient data': { bar: 'bg-[#f9fafb] border-[#e4e7ec]', text: 'text-[#344054]', dot: 'bg-[#98a2b3]', meter: 'bg-[#98a2b3]' },
};

function getVStyle(v: string | null): VStyle {
  if (!v) return VSTYLES['insufficient data']!;
  return VSTYLES[v.toLowerCase()] ?? VSTYLES['insufficient data']!;
}

function confPct(c: string) { return c === 'high' ? 85 : c === 'medium' ? 55 : 25; }

// ── Elapsed timer ─────────────────────────────────────────────────────────

function ElapsedTimer({ running, isEmail }: { running: boolean; isEmail?: boolean }) {
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
      <div className="w-10 h-10 rounded-full border-2 border-[#e4e7ec] border-t-[#1570ef] animate-spin mx-auto" />
      <div>
        <p className="text-sm font-medium text-[#101828]">{stage}</p>
        <p className="text-xs font-mono text-[#98a2b3] mt-0.5">{e}s elapsed</p>
      </div>
      <div className="w-full bg-[#f2f4f7] rounded-full h-1.5 max-w-[200px] mx-auto">
        <div className="bg-[#1570ef] h-1.5 rounded-full transition-all duration-1000" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

// ── Source row ────────────────────────────────────────────────────────────

function SourceRow({ result }: { result: EnrichmentResult }) {
  const dotCls = { ok: 'bg-[#079455]', cached: 'bg-[#079455]', error: 'bg-[#d92d20]',
    rate_limited: 'bg-[#dc6803]', missing_key: 'bg-[#98a2b3]',
    unsupported_ioc: 'bg-[#98a2b3]', skipped_safety: 'bg-[#dc6803]',
  }[result.status] ?? 'bg-[#98a2b3]';
  const hasData = result.status === 'ok' || result.status === 'cached';
  return (
    <div className={`flex items-start gap-2.5 px-3 py-2 border-b border-[#f2f4f7] last:border-0 ${!hasData ? 'opacity-40' : ''}`}>
      <span className={`mt-1.5 w-1.5 h-1.5 rounded-full shrink-0 ${dotCls}`} />
      <div className="flex-1 min-w-0">
        <p className="text-xs font-semibold text-[#344054]">{result.providerName}</p>
        {hasData && result.summary && (
          <p className="text-[11px] text-[#667085] mt-0.5 line-clamp-2 leading-snug">{result.summary}</p>
        )}
        {!hasData && (
          <p className="text-[11px] text-[#98a2b3] mt-0.5">
            {result.status === 'missing_key' ? 'No API key' : result.status === 'rate_limited' ? 'Rate limited' : 'No data'}
          </p>
        )}
      </div>
    </div>
  );
}

// ── Action item (checkable) ───────────────────────────────────────────────

function ActionItem({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button onClick={() => setDone(v => !v)}
      className={`w-full flex items-start gap-2.5 py-2 px-1 text-left rounded transition-colors ${done ? '' : 'hover:bg-[#f9fafb]'}`}>
      <div className={`mt-0.5 w-4 h-4 rounded border shrink-0 flex items-center justify-center transition-colors ${
        done ? 'bg-[#079455] border-[#079455]' : 'bg-white border-[#d0d5dd]'}`}>
        {done && <svg className="w-2.5 h-2.5 text-white" fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>}
      </div>
      <span className={`text-xs text-[#344054] leading-relaxed ${done ? 'line-through text-[#98a2b3]' : ''}`}>{text}</span>
    </button>
  );
}

// ── Auth badge (SPF / DKIM / DMARC) ──────────────────────────────────────

function AuthBadge({ label, result }: { label: string; result: string | null }) {
  const r = result?.toLowerCase();
  const { bg, border, ink, dot } = r === 'pass'
    ? { bg: 'bg-[#ecfdf3]', border: 'border-[#abefc6]', ink: 'text-[#067647]', dot: 'bg-[#079455]' }
    : r === 'fail' || r === 'permerror'
    ? { bg: 'bg-[#fef3f2]', border: 'border-[#fecdca]', ink: 'text-[#b42318]', dot: 'bg-[#d92d20]' }
    : r === 'softfail' || r === 'temperror' || r === 'neutral'
    ? { bg: 'bg-[#fffaeb]', border: 'border-[#fedf89]', ink: 'text-[#b54708]', dot: 'bg-[#dc6803]' }
    : { bg: 'bg-[#f2f4f7]', border: 'border-[#e4e7ec]', ink: 'text-[#667085]', dot: 'bg-[#98a2b3]' };

  return (
    <div className={`flex flex-col items-center gap-1 px-3 py-2 rounded-lg border ${bg} ${border}`}>
      <p className="text-[10px] font-bold uppercase tracking-widest" style={{ color: 'inherit' }}>
        <span className={ink}>{label}</span>
      </p>
      <div className="flex items-center gap-1">
        <span className={`w-1.5 h-1.5 rounded-full ${dot}`} />
        <span className={`text-xs font-semibold font-mono ${ink}`}>{result ?? 'none'}</span>
      </div>
    </div>
  );
}

// ── Email auth summary card ───────────────────────────────────────────────

function EmailAuthCard({ parsed }: { parsed: ParsedEmailHeaders }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="border border-[#e4e7ec] rounded-[10px] overflow-hidden">
      {/* Auth row */}
      <div className="p-3 bg-[#fafbfc] border-b border-[#f2f4f7]">
        <p className="wb-label mb-2">Email Authentication</p>
        <div className="grid grid-cols-3 gap-2">
          <AuthBadge label="SPF"   result={parsed.spf} />
          <AuthBadge label="DKIM"  result={parsed.dkim} />
          <AuthBadge label="DMARC" result={parsed.dmarc} />
        </div>
      </div>

      {/* Suspicious indicators */}
      {parsed.suspiciousIndicators.length > 0 && (
        <div className="px-3 py-2.5 bg-[#fffaeb] border-b border-[#fedf89]">
          <p className="text-[11px] font-bold uppercase tracking-wider text-[#b54708] mb-1.5">
            Suspicious indicators ({parsed.suspiciousIndicators.length})
          </p>
          {parsed.suspiciousIndicators.map((s, i) => (
            <div key={i} className="flex items-start gap-1.5 mb-1 last:mb-0">
              <svg className="w-3 h-3 text-[#dc6803] shrink-0 mt-0.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01M12 3l9 16H3L12 3z" />
              </svg>
              <span className="text-[11px] text-[#b54708]">{s}</span>
            </div>
          ))}
        </div>
      )}

      {/* Header summary rows */}
      <div className="divide-y divide-[#f2f4f7]">
        {[
          { label: 'Sending IP',   value: parsed.sendingIp },
          { label: 'From',         value: parsed.fromAddress },
          { label: 'Return-Path',  value: parsed.returnPathDomain ? `@${parsed.returnPathDomain}` : null },
          { label: 'DKIM domain',  value: parsed.dkimDomain },
          { label: 'Reply-To',     value: parsed.replyToDomain ? `@${parsed.replyToDomain}` : null },
        ].map(({ label, value }) => value ? (
          <div key={label} className="flex items-baseline gap-2 px-3 py-1.5">
            <span className="text-[11px] text-[#98a2b3] w-20 shrink-0">{label}</span>
            <code className="text-[11px] font-mono text-[#344054] break-all">{value}</code>
          </div>
        ) : null)}
      </div>

      {/* Hop toggle */}
      {parsed.hops.length > 0 && (
        <div className="border-t border-[#f2f4f7]">
          <button
            onClick={() => setExpanded(v => !v)}
            className="w-full flex items-center justify-between px-3 py-2 text-[11px] text-[#98a2b3] hover:text-[#667085] transition-colors"
          >
            <span className="font-semibold uppercase tracking-wider">Received hops ({parsed.hops.length})</span>
            <svg className={`w-3 h-3 transition-transform ${expanded ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
            </svg>
          </button>
          {expanded && (
            <div className="px-3 pb-2 space-y-1.5">
              {parsed.hops.map((h, i) => (
                <div key={i} className="text-[10px] font-mono text-[#667085] bg-[#fafbfc] rounded p-1.5 break-all leading-relaxed">
                  {h.slice(0, 120)}{h.length > 120 ? '…' : ''}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Narrative view ────────────────────────────────────────────────────────

function NarrativeView({
  narrative,
  results,
  overall,
  ollamaModel,
  analysedAt,
  emailParsed,
}: {
  narrative: string;
  results: EnrichmentResult[];
  overall: AnalysisResponse['overall'];
  ollamaModel: string;
  analysedAt: string;
  emailParsed?: ParsedEmailHeaders;
}) {
  const parsed = parseNarrative(narrative);
  const s = getVStyle(parsed.verdict);
  const [showSrc, setShowSrc] = useState(false);
  const [showNotes, setShowNotes] = useState(false);
  const dataCount = results.filter(r => r.status === 'ok' || r.status === 'cached').length;
  const pct = confPct(overall.confidence);

  if (!parsed.verdict && parsed.findings.length === 0 && parsed.actions.length === 0) {
    return <pre className="text-xs text-[#475467] whitespace-pre-wrap leading-relaxed font-sans p-4 bg-[#fafbfc] rounded-lg border border-[#e4e7ec]">{narrative}</pre>;
  }

  return (
    <div className="space-y-4">
      {/* Email auth summary (when available) */}
      {emailParsed && <EmailAuthCard parsed={emailParsed} />}

      {/* Verdict */}
      {parsed.verdict && (
        <div className={`rounded-[10px] border p-4 ${s.bar}`}>
          <p className="text-[11px] font-semibold uppercase tracking-wider opacity-60 mb-1">Analyst Verdict</p>
          <p className={`text-xl font-bold tracking-wide ${s.text}`}>{parsed.verdict}</p>
          <div className="mt-3 space-y-1">
            <div className="flex items-center justify-between">
              <span className={`text-[11px] font-medium opacity-60 ${s.text}`}>Confidence</span>
              <span className={`text-lg font-bold font-mono ${s.text}`}>{pct}%</span>
            </div>
            <div className="w-full bg-white/50 rounded-full h-1.5">
              <div className={`h-1.5 rounded-full transition-all duration-700 ${s.meter}`} style={{ width: `${pct}%` }} />
            </div>
            <p className={`text-[10px] opacity-50 ${s.text}`}>{dataCount}/{results.length} sources returned data</p>
          </div>
        </div>
      )}

      {/* Key Findings */}
      {parsed.findings.length > 0 && (
        <div className="space-y-2">
          <p className="wb-label">Key Findings</p>
          {parsed.findings.map((f, i) => (
            <div key={i} className="flex gap-2.5 text-xs text-[#344054] leading-relaxed">
              <span className={`mt-1.5 w-1.5 h-1.5 rounded-full shrink-0 ${s.dot}`} />
              <span>{f}</span>
            </div>
          ))}
        </div>
      )}

      {/* Enrichment Sources */}
      <div>
        <button onClick={() => setShowSrc(v => !v)}
          className="flex items-center gap-1.5 wb-label hover:text-[#475467] transition-colors w-full text-left">
          <svg className={`w-3 h-3 transition-transform ${showSrc ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
          </svg>
          Enrichment Sources
          <span className="ml-auto font-mono font-normal normal-case tracking-normal text-[#98a2b3]">{dataCount}/{results.length}</span>
        </button>
        {showSrc && (
          <div className="mt-2 border border-[#e4e7ec] rounded-[10px] overflow-hidden">
            {results.map(r => <SourceRow key={r.providerId} result={r} />)}
          </div>
        )}
      </div>

      {/* Recommended Actions */}
      {parsed.actions.length > 0 && (
        <div className="space-y-1">
          <p className="wb-label">Recommended Actions</p>
          <div className="divide-y divide-[#f2f4f7]">
            {parsed.actions.map((a, i) => <ActionItem key={i} text={a} />)}
          </div>
        </div>
      )}

      {/* Analyst Notes */}
      {parsed.notes && (
        <div>
          <button onClick={() => setShowNotes(v => !v)}
            className="flex items-center gap-1.5 wb-label hover:text-[#475467] transition-colors">
            <svg className={`w-3 h-3 transition-transform ${showNotes ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
            </svg>
            Analyst Notes
          </button>
          {showNotes && (
            <p className="mt-2 text-xs text-[#475467] leading-relaxed p-3 bg-[#fafbfc] rounded-lg border border-[#e4e7ec]">{parsed.notes}</p>
          )}
        </div>
      )}

      <p className="text-[10px] font-mono text-[#98a2b3]">{new Date(analysedAt).toLocaleTimeString()} · {ollamaModel}</p>
    </div>
  );
}

// ── Main ──────────────────────────────────────────────────────────────────

function SparkIcon() {
  return (
    <svg className="w-[18px] h-[18px]" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 2l2.4 7.4H22l-6.2 4.5 2.4 7.4L12 17l-6.2 4.3 2.4-7.4L2 9.4h7.6L12 2z" />
    </svg>
  );
}

type AnyResult = AnalysisResponse | EmailHeaderAnalysisResponse;

export function AutoAnalysisPanel({ ioc, workflowId, onComplete, onPivot: _onPivot, autoRun, onAutoRunConsumed }: AutoAnalysisPanelProps) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnyResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [includeHunter, setIncludeHunter] = useState(false);
  // Tracks the current run so stale results from previous in-flight requests are discarded.
  const runGenRef = useRef(0);

  const isEmailHeader = ioc?.isEmailHeader === true;
  const disabled = !ioc || (ioc.type === 'unknown' && !isEmailHeader);
  const hunterApplicable = ioc?.type === 'domain' || ioc?.type === 'url' || ioc?.type === 'email';
  const hunterLabel = ioc?.type === 'email'
    ? 'email verify + person enrichment (uses 2 credits)'
    : 'company profile & email intel (uses 1 credit)';

  useEffect(() => {
    runGenRef.current++;   // invalidate any in-flight analysis for the previous IOC
    setLoading(false);     // un-disable the button immediately on IOC change
    setResult(null);
    setError(null);
    if (autoRun && ioc && !disabled) {
      onAutoRunConsumed?.();
      void handleRun(false);
    }
  }, [ioc?.normalised, workflowId]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleRun = useCallback(async (forceRefresh = false) => {
    if (!ioc || disabled) return;
    const snap = ioc;
    const gen = ++runGenRef.current;
    setLoading(true); setError(null); setResult(null);
    try {
      if (snap.isEmailHeader) {
        const r = await runEmailHeaderAnalysis({
          rawHeaders: snap.original,
          options: { forceRefresh },
        });
        if (runGenRef.current !== gen) return;
        if (!r) setError('Analysis failed — check the backend is running.');
        else setResult(r);
      } else {
        const r = await runAutoAnalysis({
          ioc: { original: snap.original, normalised: snap.normalised, type: snap.type },
          workflowId: workflowId ?? undefined,
          options: { forceRefresh, includeHunter },
        });
        if (runGenRef.current !== gen) return;
        if (!r) { setError('Analysis failed — check the backend is running.'); }
        else { setResult(r); onComplete?.(r); }
      }
    } catch (err) {
      if (runGenRef.current !== gen) return;
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      if (runGenRef.current === gen) setLoading(false);
    }
  }, [ioc, workflowId, disabled, onComplete]); // onComplete is stable (useCallback in App)

  // Discriminate the two result shapes
  const emailResult = result && 'parsed' in result ? result as EmailHeaderAnalysisResponse : null;
  const iocResult   = result && 'ioc' in result   ? result as AnalysisResponse             : null;

  const idleDesc = isEmailHeader
    ? 'Parses headers, enriches the sending IP and From domain, and generates an email security verdict.'
    : 'Queries all providers and generates a structured verdict via Ollama. ~30–60 s.';

  return (
    <div className="wb-card overflow-hidden">
      {/* Card header */}
      <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#f2f4f7]">
        <div className="flex items-center gap-2.5">
          <div className="w-[34px] h-[34px] rounded-[9px] bg-[#f2f4f7] text-[#475467] flex items-center justify-center">
            <SparkIcon />
          </div>
          <div>
            <p className="text-[13px] font-semibold text-[#101828]">Auto Analysis</p>
            <p className="text-[11px] text-[#98a2b3]">
              {isEmailHeader ? 'Email security verdict' : 'AI-assisted verdict'}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {result && !loading && (
            <button onClick={() => void handleRun(true)}
              className="text-xs font-medium px-3 py-1.5 rounded-lg border border-[#e4e7ec] bg-white text-[#475467] hover:border-[#d0d5dd] transition-colors">
              Re-run
            </button>
          )}
          <button onClick={() => void handleRun(false)} disabled={loading || disabled}
            className="text-xs font-semibold px-3.5 py-1.5 rounded-lg bg-[#1570ef] text-white hover:bg-[#175cd3] transition-colors disabled:opacity-40 disabled:cursor-not-allowed">
            Run Analysis
          </button>
        </div>
      </div>

      {/* Hunter toggle — only for domain/url IOCs */}
      {hunterApplicable && (
        <div className="flex items-center justify-between px-5 py-2.5 border-b border-[#f2f4f7] bg-[#fafbfc]">
          <div className="flex items-center gap-2">
            <svg className="w-3.5 h-3.5 text-[#98a2b3] shrink-0" fill="none" stroke="currentColor" strokeWidth={1.8} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35M17 11A6 6 0 1 1 5 11a6 6 0 0 1 12 0z" />
            </svg>
            <span className="text-xs font-medium text-[#344054]">Include Hunter.io</span>
            <span className="text-[11px] text-[#98a2b3]">— {hunterLabel}</span>
          </div>
          <button
            role="switch"
            aria-checked={includeHunter}
            onClick={() => setIncludeHunter(v => !v)}
            disabled={loading}
            className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 focus:outline-none disabled:opacity-40 disabled:cursor-not-allowed ${
              includeHunter ? 'bg-[#1570ef]' : 'bg-[#d0d5dd]'
            }`}
          >
            <span className={`pointer-events-none inline-block h-4 w-4 rounded-full bg-white shadow-sm ring-0 transition-transform duration-200 ${
              includeHunter ? 'translate-x-4' : 'translate-x-0'
            }`} />
          </button>
        </div>
      )}

      {/* Body */}
      <div className="p-5">
        {!loading && !result && !error && (
          <div className="text-center py-8 space-y-3">
            <div className="w-10 h-10 rounded-xl bg-[#f2f4f7] flex items-center justify-center mx-auto text-[#98a2b3]">
              <SparkIcon />
            </div>
            <div>
              <p className="text-sm font-medium text-[#101828]">Ready to analyse</p>
              <p className="text-xs text-[#98a2b3] mt-1 max-w-[260px] mx-auto leading-relaxed">
                {idleDesc}
              </p>
            </div>
          </div>
        )}

        {loading && <ElapsedTimer running isEmail={isEmailHeader} />}

        {error && !loading && (
          <div className="flex gap-2.5 p-3 rounded-lg bg-[#fef3f2] border border-[#fecdca] text-xs text-[#b42318]">
            <svg className="w-4 h-4 shrink-0 mt-0.5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
              <circle cx="12" cy="12" r="10" /><path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4m0 4h.01" />
            </svg>
            {error}
          </div>
        )}

        {/* Email header result */}
        {emailResult && !loading && (
          emailResult.narrative
            ? <NarrativeView
                narrative={emailResult.narrative}
                results={emailResult.results}
                overall={emailResult.overall}
                ollamaModel={emailResult.ollamaModel}
                analysedAt={emailResult.analysedAt}
                emailParsed={emailResult.parsed}
              />
            : (
              <div className="space-y-3">
                <EmailAuthCard parsed={emailResult.parsed} />
                <div className="flex gap-2.5 p-3 rounded-lg bg-[#fffaeb] border border-[#fedf89] text-xs text-[#b54708]">
                  <svg className="w-4 h-4 shrink-0 mt-0.5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0zM12 9v4m0 4h.01" />
                  </svg>
                  <span><strong>Narrative unavailable</strong> — {emailResult.narrativeError ?? 'Ollama did not respond.'}</span>
                </div>
                <div className="border border-[#e4e7ec] rounded-[10px] overflow-hidden">
                  {emailResult.results.map(r => <SourceRow key={r.providerId} result={r} />)}
                </div>
              </div>
            )
        )}

        {/* Standard IOC result */}
        {iocResult && !loading && (
          iocResult.narrative
            ? <NarrativeView
                narrative={iocResult.narrative}
                results={iocResult.results}
                overall={iocResult.overall}
                ollamaModel={iocResult.ollamaModel}
                analysedAt={iocResult.analysedAt}
              />
            : (
              <div className="space-y-3">
                <div className="flex gap-2.5 p-3 rounded-lg bg-[#fffaeb] border border-[#fedf89] text-xs text-[#b54708]">
                  <svg className="w-4 h-4 shrink-0 mt-0.5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0zM12 9v4m0 4h.01" />
                  </svg>
                  <span><strong>Narrative unavailable</strong> — {iocResult.narrativeError ?? 'Ollama did not respond.'}</span>
                </div>
                <div className="border border-[#e4e7ec] rounded-[10px] overflow-hidden">
                  {iocResult.results.map(r => <SourceRow key={r.providerId} result={r} />)}
                </div>
              </div>
            )
        )}
      </div>
    </div>
  );
}
