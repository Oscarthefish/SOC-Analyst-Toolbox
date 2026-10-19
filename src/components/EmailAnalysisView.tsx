import { useState, useCallback } from 'react';
import type { EmailHeaderAnalysisResponse, ParsedEmailHeaders, AnalysisResponse } from '../types/analysis';
import type { EnrichmentResult } from '../types/enrichment';
import { ProviderComparisonPanel } from './enrichmentShared';
import { parseNarrative, buildSourceMap, findSourceUrl } from '../lib/narrative';

/** Result view for raw email header analysis: authentication, routing and sender reputation. */


const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4, benign: 5 };

function sortBySeverity(results: EnrichmentResult[]): EnrichmentResult[] {
  return [...results].sort((a, b) => (SEVERITY_RANK[a.severity] ?? 4) - (SEVERITY_RANK[b.severity] ?? 4));
}

// ── Verdict styling ───────────────────────────────────────────────────────

interface VStyle { bar: string; text: string; dot: string; }

const VSTYLES: Record<string, VStyle> = {
  'benign':            { bar: 'bg-ok-bg border-ok-line', text: 'text-ok-fg', dot: 'bg-ok' },
  'low risk':          { bar: 'bg-accent-bg border-accent-line', text: 'text-accent-fg', dot: 'bg-accent' },
  'suspicious':        { bar: 'bg-warn-bg border-warn-line', text: 'text-warn-fg', dot: 'bg-warn' },
  'likely malicious':  { bar: 'bg-high-bg border-high-line', text: 'text-high-fg', dot: 'bg-high' },
  'malicious':         { bar: 'bg-danger-bg border-danger-line', text: 'text-danger-fg', dot: 'bg-danger' },
  'insufficient data': { bar: 'bg-inset border-line', text: 'text-fg-2', dot: 'bg-fg-4' },
};

function getVStyle(v: string | null): VStyle {
  if (!v) return VSTYLES['insufficient data']!;
  return VSTYLES[v.toLowerCase()] ?? VSTYLES['insufficient data']!;
}


// ── Source row ────────────────────────────────────────────────────────────

function SourceRow({ result }: { result: EnrichmentResult }) {
  const dotCls = { ok: 'bg-ok', cached: 'bg-ok', error: 'bg-danger',
    rate_limited: 'bg-warn', missing_key: 'bg-fg-4',
    unsupported_ioc: 'bg-fg-4', skipped_safety: 'bg-warn',
  }[result.status] ?? 'bg-fg-4';
  const hasData = result.status === 'ok' || result.status === 'cached';
  return (
    <div className={`flex items-start gap-2.5 px-3 py-2 border-b border-line-soft last:border-0 ${!hasData ? 'bg-inset' : ''}`}>
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
          <p className="text-[11px] font-semibold uppercase tracking-wider text-fg-3 mb-1">Local LLM verdict</p>
          <p className={`text-xl font-bold tracking-wide ${s.text}`}>{parsed.verdict}</p>
          <p className="mt-1 text-xs text-fg-3">
            <span className="capitalize">{overall.confidence}</span> confidence · {dataCount}/{results.length} sources returned data
          </p>
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

export function EmailAnalysisView({ result: emailResult, iocType }: { result: EmailHeaderAnalysisResponse; iocType?: string }) {
  return (
    <>
        {(
          emailResult.narrative
            ? <NarrativeView
                narrative={emailResult.narrative}
                results={emailResult.results}
                overall={emailResult.overall}
                ollamaModel={emailResult.ollamaModel}
                analysedAt={emailResult.analysedAt}
                emailParsed={emailResult.parsed}
                iocType={emailResult.ipIoc?.type ?? emailResult.domIoc?.type ?? iocType}
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

    </>
  );
}
