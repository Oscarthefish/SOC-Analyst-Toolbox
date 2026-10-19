import { useState, useCallback, useEffect, useLayoutEffect, useRef, forwardRef, useImperativeHandle } from 'react';
import type { DetectedIoc } from '../types/ioc';
import type { AnalysisResponse, EmailHeaderAnalysisResponse, ParsedEmailHeaders } from '../types/analysis';
import type { EnrichmentResult } from '../types/enrichment';
import { runAutoAnalysis, runEmailHeaderAnalysis } from '../lib/apiClient';
import { ProviderComparisonPanel } from './enrichmentShared';

export interface AutoAnalysisPanelHandle {
  run: (forceRefresh?: boolean) => void;
}

interface AutoAnalysisPanelProps {
  ioc: DetectedIoc | null;
  workflowId: string | null;
  onComplete?: (response: AnalysisResponse | null) => void;
  onPivot?: (iocValue: string) => void;
  preloadResult?: AnalysisResponse | null;
  hideHeader?: boolean;
  onLoadingChange?: (loading: boolean) => void;
}

// ── Severity sort ─────────────────────────────────────────────────────────

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4, benign: 5 };

function sortBySeverity(results: EnrichmentResult[]): EnrichmentResult[] {
  return [...results].sort((a, b) => (SEVERITY_RANK[a.severity] ?? 4) - (SEVERITY_RANK[b.severity] ?? 4));
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
  'benign':            { bar: 'bg-ok-bg border-ok-line', text: 'text-ok-fg', dot: 'bg-ok', meter: 'bg-ok' },
  'low risk':          { bar: 'bg-accent-bg border-accent-line', text: 'text-accent-fg', dot: 'bg-accent', meter: 'bg-accent' },
  'suspicious':        { bar: 'bg-warn-bg border-warn-line', text: 'text-warn-fg', dot: 'bg-warn', meter: 'bg-warn' },
  'likely malicious':  { bar: 'bg-high-bg border-high-line', text: 'text-high-fg', dot: 'bg-high', meter: 'bg-high' },
  'malicious':         { bar: 'bg-danger-bg border-danger-line', text: 'text-danger-fg', dot: 'bg-danger', meter: 'bg-danger' },
  'insufficient data': { bar: 'bg-inset border-line', text: 'text-fg-2', dot: 'bg-fg-4', meter: 'bg-fg-4' },
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

// ── Source row ────────────────────────────────────────────────────────────

function SourceRow({ result }: { result: EnrichmentResult }) {
  const dotCls = { ok: 'bg-ok', cached: 'bg-ok', error: 'bg-danger',
    rate_limited: 'bg-warn', missing_key: 'bg-fg-4',
    unsupported_ioc: 'bg-fg-4', skipped_safety: 'bg-warn',
  }[result.status] ?? 'bg-fg-4';
  const hasData = result.status === 'ok' || result.status === 'cached';
  return (
    <div className={`flex items-start gap-2.5 px-3 py-2 border-b border-line-soft last:border-0 ${!hasData ? 'opacity-40' : ''}`}>
      <span className={`mt-1.5 w-1.5 h-1.5 rounded-full shrink-0 ${dotCls}`} />
      <div className="flex-1 min-w-0">
        <p className="text-xs font-semibold text-fg-2">{result.providerName}</p>
        {hasData && result.summary && (
          <p className="text-[11px] text-fg-3 mt-0.5 line-clamp-2 leading-snug">{result.summary}</p>
        )}
        {!hasData && (
          <p className="text-[11px] text-fg-4 mt-0.5">
            {result.status === 'missing_key' ? 'No API key' : result.status === 'rate_limited' ? 'Rate limited' : 'No data'}
          </p>
        )}
      </div>
    </div>
  );
}

// ── Auth badge (SPF / DKIM / DMARC) ──────────────────────────────────────

function AuthBadge({ label, result, subtitle }: { label: string; result: string | null; subtitle?: string }) {
  const r = result?.toLowerCase();
  const { bg, border, ink, dot } = r === 'pass'
    ? { bg: 'bg-ok-bg', border: 'border-ok-line', ink: 'text-ok-fg', dot: 'bg-ok' }
    : r === 'fail' || r === 'permerror'
    ? { bg: 'bg-danger-bg', border: 'border-danger-line', ink: 'text-danger-fg', dot: 'bg-danger' }
    : r === 'softfail' || r === 'temperror' || r === 'neutral'
    ? { bg: 'bg-warn-bg', border: 'border-warn-line', ink: 'text-warn-fg', dot: 'bg-warn' }
    : { bg: 'bg-raised', border: 'border-line', ink: 'text-fg-3', dot: 'bg-fg-4' };

  return (
    <div className={`flex flex-col items-center gap-0.5 px-3 py-2 rounded-lg border ${bg} ${border}`}>
      <span className={`text-[10px] font-bold uppercase tracking-widest ${ink}`}>{label}</span>
      <div className="flex items-center gap-1">
        <span className={`w-1.5 h-1.5 rounded-full ${dot}`} />
        <span className={`text-xs font-semibold font-mono ${ink}`}>{result ?? 'none'}</span>
      </div>
      {subtitle && (
        <span className="text-[9px] font-mono text-fg-4 mt-0.5">{subtitle}</span>
      )}
    </div>
  );
}

// Helper: extract bare email from "Display Name <email@domain>" or plain address
function extractEmail(addr: string | null): string | null {
  if (!addr) return null;
  const angle = addr.match(/<([^>@]+@[^>]+)>/);
  if (angle) return angle[1].toLowerCase();
  const bare = addr.match(/\b([^\s@,;]+@[^\s@,;]+)\b/);
  return bare ? bare[1].toLowerCase() : null;
}

// Helper: extract display name from "Display Name <email@domain>"
function extractDisplayName(addr: string | null): string | null {
  if (!addr) return null;
  const angle = addr.match(/^(.+?)\s*<[^>]+>/);
  if (angle) return angle[1].trim().replace(/^["']|["']$/g, '') || null;
  return null;
}

// ── Email auth summary card ───────────────────────────────────────────────

function EmailAuthCard({ parsed }: { parsed: ParsedEmailHeaders }) {
  const [showDetails, setShowDetails] = useState(false);

  const isSelfSent = parsed.suspiciousIndicators.some(s => s.startsWith('Self-sent'));
  const spamScoreNum = parsed.spamScore !== null ? parseFloat(parsed.spamScore) : NaN;
  const spamHigh = !isNaN(spamScoreNum) && spamScoreNum >= 10;
  const spamMedium = !isNaN(spamScoreNum) && spamScoreNum >= 5 && spamScoreNum < 10;

  const fromEmail = extractEmail(parsed.fromAddress);
  const fromDisplay = extractDisplayName(parsed.fromAddress);
  const toEmail = extractEmail(parsed.toAddress);
  const toDisplay = extractDisplayName(parsed.toAddress);

  return (
    <div className="border border-line rounded-lg overflow-hidden">

      {/* ── Self-sent warning banner ── */}
      {isSelfSent && (
        <div className="flex items-center gap-2 px-3 py-2 bg-danger-bg border-b border-danger-line">
          <svg className="w-3.5 h-3.5 text-danger-fg shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01M12 3l9 16H3L12 3z" />
          </svg>
          <span className="text-[11px] font-bold text-danger-fg uppercase tracking-wide">Self-sent — sender and recipient are the same address</span>
        </div>
      )}

      {/* ── FROM / TO envelope ── */}
      <div className="p-3 bg-surface border-b border-line-soft space-y-2">
        {/* FROM */}
        <div className="flex items-start gap-2.5">
          <span className="text-[10px] font-bold uppercase tracking-widest text-fg-4 w-6 pt-0.5 shrink-0">FROM</span>
          <div className="min-w-0">
            {fromDisplay && (
              <p className="text-[13px] font-semibold text-fg-1 leading-tight truncate">{fromDisplay}</p>
            )}
            <p className={`font-mono text-[12px] break-all leading-snug ${fromDisplay ? 'text-fg-3' : 'text-fg-1 font-semibold'}`}>
              {fromEmail ?? parsed.fromAddress ?? <span className="text-fg-4">unknown</span>}
            </p>
          </div>
        </div>

        {/* TO */}
        <div className="flex items-start gap-2.5">
          <span className="text-[10px] font-bold uppercase tracking-widest text-fg-4 w-6 pt-0.5 shrink-0">TO</span>
          <div className="min-w-0">
            {toDisplay && (
              <p className="text-[13px] font-semibold text-fg-1 leading-tight truncate">{toDisplay}</p>
            )}
            <p className={`font-mono text-[12px] break-all leading-snug ${toDisplay ? 'text-fg-3' : 'text-fg-1 font-semibold'}`}>
              {toEmail ?? parsed.toAddress ?? <span className="text-fg-4">unknown</span>}
            </p>
          </div>
        </div>

        {/* Subject */}
        {parsed.subject && (
          <div className="flex items-start gap-2.5">
            <span className="text-[10px] font-bold uppercase tracking-widest text-fg-4 w-6 pt-0.5 shrink-0">RE</span>
            <p className="text-[12px] text-fg-2 leading-snug break-all">{parsed.subject}</p>
          </div>
        )}
      </div>

      {/* ── Auth badges ── */}
      <div className="p-3 bg-inset border-b border-line-soft">
        <p className="wb-label mb-2">Email Authentication</p>
        <div className="grid grid-cols-3 gap-2">
          <AuthBadge label="SPF"   result={parsed.spf} />
          <AuthBadge label="DKIM"  result={parsed.dkim} />
          <AuthBadge
            label="DMARC"
            result={parsed.dmarc}
            subtitle={parsed.dmarcPolicy ? `policy=${parsed.dmarcPolicy}` : undefined}
          />
        </div>
      </div>

      {/* ── Spam score ── */}
      {parsed.spamScore !== null && (
        <div className={`flex items-center justify-between px-3 py-2 border-b ${
          spamHigh   ? 'bg-danger-bg border-danger-line' :
          spamMedium ? 'bg-warn-bg border-warn-line' :
                       'bg-inset border-line-soft'
        }`}>
          <span className={`text-[11px] font-bold uppercase tracking-wide ${
            spamHigh ? 'text-danger-fg' : spamMedium ? 'text-warn-fg' : 'text-fg-3'
          }`}>Spam Score</span>
          <span className={`text-[13px] font-bold font-mono ${
            spamHigh ? 'text-danger-fg' : spamMedium ? 'text-warn-fg' : 'text-fg-2'
          }`}>{parsed.spamScore}{spamHigh ? ' ⚠ HIGH' : ''}</span>
        </div>
      )}

      {/* ── Suspicious indicators (non-self-sent) ── */}
      {parsed.suspiciousIndicators.filter(s => !s.startsWith('Self-sent')).length > 0 && (
        <div className="px-3 py-2.5 bg-warn-bg border-b border-warn-line">
          <p className="text-[11px] font-bold uppercase tracking-wider text-warn-fg mb-1.5">
            Suspicious indicators
          </p>
          {parsed.suspiciousIndicators.filter(s => !s.startsWith('Self-sent') && !s.startsWith('High spam')).map((s, i) => (
            <div key={i} className="flex items-start gap-1.5 mb-1 last:mb-0">
              <svg className="w-3 h-3 text-warn-fg shrink-0 mt-0.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01M12 3l9 16H3L12 3z" />
              </svg>
              <span className="text-[11px] text-warn-fg">{s}</span>
            </div>
          ))}
        </div>
      )}

      {/* ── Collapsible technical details ── */}
      <div className="border-t border-line-soft">
        <button
          onClick={() => setShowDetails(v => !v)}
          className="w-full flex items-center justify-between px-3 py-2 text-[11px] text-fg-4 hover:text-fg-3 transition-colors"
        >
          <span className="font-semibold uppercase tracking-wider">Technical details</span>
          <svg className={`w-3 h-3 transition-transform ${showDetails ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
          </svg>
        </button>
        {showDetails && (
          <div className="divide-y divide-line-soft">
            {[
              { label: 'Sending IP',   value: parsed.sendingIp },
              { label: 'Delivered-To', value: parsed.deliveredTo },
              { label: 'Return-Path',  value: parsed.returnPathDomain ? `@${parsed.returnPathDomain}` : null },
              { label: 'DKIM domain',  value: parsed.dkimDomain },
              { label: 'Reply-To',     value: parsed.replyToAddress ?? (parsed.replyToDomain ? `@${parsed.replyToDomain}` : null) },
              { label: 'Message-ID',   value: parsed.messageId },
              { label: 'Date',         value: parsed.date },
            ].map(({ label, value }) => value ? (
              <div key={label} className="flex items-baseline gap-2 px-3 py-1.5">
                <span className="text-[11px] text-fg-4 w-24 shrink-0">{label}</span>
                <code className="text-[11px] font-mono text-fg-2 break-all">{value}</code>
              </div>
            ) : null)}

            {/* Hops */}
            {parsed.hops.length > 0 && (
              <div className="px-3 py-2 space-y-1.5">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-fg-4 mb-1">
                  Received hops ({parsed.hops.length})
                </p>
                {parsed.hops.map((h, i) => (
                  <div key={i} className="text-[10px] font-mono text-fg-3 bg-inset rounded p-1.5 break-all leading-relaxed">
                    {h.slice(0, 120)}{h.length > 120 ? '…' : ''}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Narrative view ────────────────────────────────────────────────────────

// Build a map of lowercase provider name/id keywords → sourceUrl
function buildSourceMap(results: EnrichmentResult[]): Map<string, string> {
  const map = new Map<string, string>();
  for (const r of results) {
    if (!r.sourceUrl) continue;
    map.set(r.providerName.toLowerCase(), r.sourceUrl);
    map.set(r.providerId.toLowerCase(), r.sourceUrl);
  }
  return map;
}

function findSourceUrl(finding: string, sourceMap: Map<string, string>): string | null {
  const lower = finding.toLowerCase();
  for (const [key, url] of sourceMap) {
    if (lower.includes(key)) return url;
  }
  return null;
}

function CopySummaryButton({ verdict, findings }: { verdict: string | null; findings: string[] }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = useCallback(() => {
    const lines: string[] = [];
    if (verdict) lines.push(`VERDICT: ${verdict}`, '');
    if (findings.length > 0) {
      lines.push('KEY FINDINGS:');
      findings.forEach(f => lines.push(`• ${f}`));
    }
    void navigator.clipboard.writeText(lines.join('\n')).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [verdict, findings]);

  return (
    <button
      onClick={handleCopy}
      title="Copy verdict and findings"
      className="flex items-center gap-1 text-[11px] text-fg-3 hover:text-fg-2 font-medium transition-colors"
    >
      {copied ? (
        <>
          <svg className="w-3 h-3 text-ok-fg" fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
          </svg>
          <span className="text-ok-fg">Copied</span>
        </>
      ) : (
        <>
          <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth={1.8} viewBox="0 0 24 24">
            <rect x="9" y="9" width="13" height="13" rx="2" />
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
          </svg>
          Copy
        </>
      )}
    </button>
  );
}

function NarrativeView({
  narrative,
  results,
  overall,
  ollamaModel,
  analysedAt,
  emailParsed,
  iocType,
}: {
  narrative: string;
  results: EnrichmentResult[];
  overall: AnalysisResponse['overall'];
  ollamaModel: string;
  analysedAt: string;
  emailParsed?: ParsedEmailHeaders;
  iocType?: string;
}) {
  const parsed = parseNarrative(narrative);
  const s = getVStyle(parsed.verdict);
  const [showSrc, setShowSrc] = useState(false);
  const sortedResults = sortBySeverity(results);
  const dataCount = sortedResults.filter(r => r.status === 'ok' || r.status === 'cached').length;
  const pct = confPct(overall.confidence);
  const sourceMap = buildSourceMap(sortedResults);

  if (!parsed.verdict && parsed.findings.length === 0 && parsed.actions.length === 0) {
    return <pre className="text-xs text-fg-2 whitespace-pre-wrap leading-relaxed font-sans p-4 bg-inset rounded-lg border border-line">{narrative}</pre>;
  }

  return (
    <div className="space-y-4">
      {/* Email auth summary (when available) */}
      {emailParsed && <EmailAuthCard parsed={emailParsed} />}

      {/* Verdict */}
      {parsed.verdict && (
        <div className={`rounded-lg border p-4 ${s.bar}`}>
          <p className="text-[11px] font-semibold uppercase tracking-wider opacity-60 mb-1">Analyst Verdict</p>
          <p className={`text-xl font-bold tracking-wide ${s.text}`}>{parsed.verdict}</p>
          <div className="mt-3 space-y-1">
            <div className="flex items-center justify-between">
              <span className={`text-[11px] font-medium opacity-60 ${s.text}`}>Confidence</span>
              <span className={`text-lg font-bold font-mono ${s.text}`}>{pct}%</span>
            </div>
            <div className="w-full bg-surface/50 rounded-full h-1.5">
              <div className={`h-1.5 rounded-full transition-all duration-700 ${s.meter}`} style={{ width: `${pct}%` }} />
            </div>
            <p className={`text-[10px] opacity-50 ${s.text}`}>{dataCount}/{results.length} sources returned data</p>
          </div>
        </div>
      )}

      {/* Provider comparison — only for email results (non-email gets this from AnalysisResultsPanel) */}
      {emailParsed && iocType && <ProviderComparisonPanel results={sortedResults} iocType={iocType} />}

      {/* Key Findings */}
      {parsed.findings.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <p className="wb-label">Key Findings</p>
            <CopySummaryButton verdict={parsed.verdict} findings={parsed.findings} />
          </div>
          {parsed.findings.map((f, i) => {
            const srcUrl = findSourceUrl(f, sourceMap);
            return (
              <div key={i} className="flex gap-2.5 text-xs text-fg-2 leading-relaxed">
                <span className={`mt-1.5 w-1.5 h-1.5 rounded-full shrink-0 ${s.dot}`} />
                <span className="flex-1">{f}</span>
                {srcUrl && (
                  <a href={srcUrl} target="_blank" rel="noopener noreferrer"
                    title="View source"
                    className="shrink-0 mt-0.5 text-accent-fg hover:text-accent-fg transition-colors">
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
                      <polyline points="15 3 21 3 21 9" />
                      <line x1="10" y1="14" x2="21" y2="3" />
                    </svg>
                  </a>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Enrichment Sources — only for email results (non-email gets provider cards from AnalysisResultsPanel) */}
      {emailParsed && (
        <div>
          <button onClick={() => setShowSrc(v => !v)}
            className="flex items-center gap-1.5 wb-label hover:text-fg-2 transition-colors w-full text-left">
            <svg className={`w-3 h-3 transition-transform ${showSrc ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
            </svg>
            Enrichment Sources
            <span className="ml-auto font-mono font-normal normal-case tracking-normal text-fg-4">{dataCount}/{results.length}</span>
          </button>
          {showSrc && (
            <div className="mt-2 border border-line rounded-lg overflow-hidden">
              {sortedResults.map(r => <SourceRow key={r.providerId} result={r} />)}
            </div>
          )}
        </div>
      )}

      {/* Analyst Notes */}
      {parsed.notes && (
        <div>
          <p className="wb-label mb-2">Analyst Notes</p>
          <p className="text-xs text-fg-2 leading-relaxed p-3 bg-inset rounded-lg border border-line">{parsed.notes}</p>
        </div>
      )}

      <p className="text-[10px] font-mono text-fg-4">{new Date(analysedAt).toLocaleTimeString()} · {ollamaModel}</p>
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

export const AutoAnalysisPanel = forwardRef<AutoAnalysisPanelHandle, AutoAnalysisPanelProps>(function AutoAnalysisPanel({ ioc, workflowId, onComplete, preloadResult, hideHeader = false, onLoadingChange }, ref) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnyResult | null>(null);
  const [error, setError] = useState<string | null>(null);
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

  // Workflow changes should clear stale results but NOT cancel an active run.
  useEffect(() => {
    setResult(null);
    setError(null);
  }, [workflowId]);

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
        const r = await runAutoAnalysis({
          ioc: { original: snap.original, normalised: snap.normalised, type: snap.type },
          workflowId: workflowId ?? undefined,
          options: { forceRefresh, includeHunter },
        });
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

  // Keep a stable ref to handleRun so the imperative handle always calls the latest version.
  const handleRunRef = useRef(handleRun);
  useLayoutEffect(() => { handleRunRef.current = handleRun; }, [handleRun]);

  // Expose run() so the parent can trigger analysis directly (no effect round-trip).
  useImperativeHandle(ref, () => ({
    run: (forceRefresh = false) => { void handleRunRef.current(forceRefresh); },
  }), []);

  // Discriminate the two result shapes
  const emailResult = result && 'parsed' in result ? result as EmailHeaderAnalysisResponse : null;
  const iocResult   = result && 'ioc' in result   ? result as AnalysisResponse             : null;

  const idleDesc = (isEmailHeader || isEmailHeaderWorkflow)
    ? 'Parses headers, enriches the sending IP and From domain, and generates an email security verdict.'
    : 'Queries all providers and generates a structured verdict via Ollama. ~30–60 s.';

  // In bar-driven mode, don't render the card at all until there is something to show.
  if (hideHeader && !loading && !result && !error) return null;

  return (
    <div className="wb-card overflow-hidden">
      {/* Card header — hidden when the AnalysisBar owns the Run button */}
      {!hideHeader && (
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-line-soft">
          <div className="flex items-center gap-2.5">
            <div className="w-[34px] h-[34px] rounded-lg bg-raised text-fg-2 flex items-center justify-center">
              <SparkIcon />
            </div>
            <div>
              <p className="text-[13px] font-semibold text-fg-1">Auto Analysis</p>
              <p className="text-[11px] text-fg-4">
                {(isEmailHeader || isEmailHeaderWorkflow) ? 'Email security verdict' : 'AI-assisted verdict'}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {result && !loading && (
              <button onClick={() => void handleRun(true)}
                className="text-xs font-medium px-3 py-1.5 rounded-lg border border-line bg-surface text-fg-2 hover:border-line-strong transition-colors">
                Re-run
              </button>
            )}
            <button onClick={() => void handleRun(false)} disabled={loading || disabled}
              className="text-xs font-semibold px-3.5 py-1.5 rounded-lg bg-accent text-white hover:bg-accent-strong transition-colors disabled:opacity-40 disabled:cursor-not-allowed">
              Run Analysis
            </button>
          </div>
        </div>
      )}

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
        {/* Idle state only shown when header is also visible (bar handles the idle prompt) */}
        {!loading && !result && !error && !hideHeader && (
          <div className="text-center py-8 space-y-3">
            <div className="w-10 h-10 rounded-xl bg-raised flex items-center justify-center mx-auto text-fg-4">
              <SparkIcon />
            </div>
            <div>
              <p className="text-sm font-medium text-fg-1">Ready to analyse</p>
              <p className="text-xs text-fg-4 mt-1 max-w-[260px] mx-auto leading-relaxed">
                {idleDesc}
              </p>
            </div>
          </div>
        )}

        {loading && <ElapsedTimer running isEmail={isEmailHeader || isEmailHeaderWorkflow} />}

        {error && !loading && (
          <div className="flex gap-2.5 p-3 rounded-lg bg-danger-bg border border-danger-line text-xs text-danger-fg">
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
                iocType={emailResult.ipIoc?.type ?? emailResult.domIoc?.type ?? ioc?.type}
              />
            : (
              <div className="space-y-3">
                <EmailAuthCard parsed={emailResult.parsed} />
                <div className="flex gap-2.5 p-3 rounded-lg bg-warn-bg border border-warn-line text-xs text-warn-fg">
                  <svg className="w-4 h-4 shrink-0 mt-0.5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0zM12 9v4m0 4h.01" />
                  </svg>
                  <span><strong>Narrative unavailable</strong> — {emailResult.narrativeError ?? 'Ollama did not respond.'}</span>
                </div>
                <div className="border border-line rounded-lg overflow-hidden">
                  {sortBySeverity(emailResult.results).map(r => <SourceRow key={r.providerId} result={r} />)}
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
                iocType={ioc?.type}
              />
            : (
              <div className="flex gap-2.5 p-3 rounded-lg bg-warn-bg border border-warn-line text-xs text-warn-fg">
                <svg className="w-4 h-4 shrink-0 mt-0.5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0zM12 9v4m0 4h.01" />
                </svg>
                <span><strong>Narrative unavailable</strong> — {iocResult.narrativeError ?? 'Ollama did not respond.'} Provider results are shown below.</span>
              </div>
            )
        )}
      </div>
    </div>
  );
});
