import { useState, useCallback, useEffect, useRef } from 'react';
import { IocTypeChip } from './IocTypeChip';
import type { DetectedIoc } from '../types/ioc';
import { detectIoc, normalizeIocInput } from '../lib/detectIoc';
import { defangUrlSmart, defangIp, defangDomain } from '../lib/defang';
import { CopyButton } from './CopyButton';
import { loadRecentIndicators as loadHistory, addRecentIndicator as addToHistory, clearRecentIndicators } from '../lib/recentIndicators';

/** Safe, well-known examples for first-time users. */
const SAMPLES = [
  { value: '185.220.101.4', note: 'Tor exit node' },
  { value: 'example.com', note: 'Reserved documentation domain' },
  { value: 'CVE-2024-3400', note: 'PAN-OS vulnerability in CISA KEV' },
  { value: '44d88612fea8a8f36de82e1278abb02f', note: 'EICAR test file (MD5)' },
];

// ── SVG icons ──────────────────────────────────────────────────────────────

function IconClock() {
  return (
    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
      <circle cx="12" cy="12" r="10" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6l4 2" />
    </svg>
  );
}

function IconX() {
  return (
    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M18 6L6 18M6 6l12 12" />
    </svg>
  );
}

// ── Type chip ──────────────────────────────────────────────────────────────

const TYPE_LABELS: Record<string, string> = {
  ipv4: 'IPv4', ipv6: 'IPv6', domain: 'Domain', url: 'URL',
  md5: 'MD5', sha1: 'SHA-1', sha256: 'SHA-256', email: 'Email',
  asn: 'ASN', cidr: 'CIDR', cve: 'CVE', unknown: 'Unknown',
};

function TypeChip({ type }: { type: string }) {
  if (type === 'unknown') {
    return (
      <span className="inline-flex items-center h-[22px] px-2 rounded text-[11px] font-semibold font-mono border bg-danger-bg border-danger-line text-danger-fg">
        Unknown
      </span>
    );
  }
  return <IocTypeChip type={type} />;
}

function ConfidenceChip({ confidence }: { confidence: 'high' | 'medium' | 'low' }) {
  const dot = { high: 'bg-ok', medium: 'bg-warn', low: 'bg-danger' }[confidence];
  return (
    <span className="inline-flex items-center gap-1.5 h-[22px] px-2 rounded text-[11px] font-medium border border-line text-fg-2">
      <span className={`w-1.5 h-1.5 rounded-full ${dot}`} />
      {confidence[0]!.toUpperCase() + confidence.slice(1)} confidence
    </span>
  );
}

// ── Defanged display ──────────────────────────────────────────────────────

function defangValue(ioc: DetectedIoc): string {
  if (ioc.type === 'url') return defangUrlSmart(ioc.normalised);
  if (ioc.type === 'ipv4' || ioc.type === 'cidr') return defangIp(ioc.normalised);
  if (ioc.type === 'domain') return defangDomain(ioc.normalised);
  if (ioc.type === 'email') {
    return ioc.normalised.replace('@', '[@]').replace(/\./g, '[.]');
  }
  return ioc.normalised;
}

// ── Classification panel ───────────────────────────────────────────────────

function Field({ k, children }: { k: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[64px_1fr] gap-2 text-xs leading-5">
      <span className="text-fg-4">{k}</span>
      <div className="min-w-0 text-fg-2">{children}</div>
    </div>
  );
}

function ClassificationCard({ ioc }: { ioc: DetectedIoc | null }) {
  const [defanged, setDefanged] = useState(false);

  useEffect(() => { setDefanged(false); }, [ioc?.normalised]);

  const canDefang = ioc && ['url', 'ipv4', 'ipv6', 'domain', 'cidr', 'email'].includes(ioc.type);
  const displayValue = ioc && defanged ? defangValue(ioc) : (ioc?.normalised ?? '');

  return (
    <div className="lg:w-[360px] shrink-0 border-t lg:border-t-0 lg:border-l border-line bg-inset p-4 flex flex-col gap-3">
      <p className="wb-label">Classification</p>

      {!ioc || (ioc.type === 'unknown' && !ioc.isEmailHeader) ? (
        <div className="flex-1 flex flex-col justify-center gap-1.5 py-4 text-xs text-fg-4">
          {ioc && ioc.type === 'unknown'
            ? <p className="text-danger-fg">Not a recognised indicator.</p>
            : <p>Waiting for input.</p>}
          <p>IPv4 · IPv6 · domain · URL · MD5 · SHA-1 · SHA-256 · email · ASN · CIDR · raw email headers</p>
        </div>
      ) : ioc.isEmailHeader ? (
        <div className="space-y-3">
          <div className="flex flex-wrap gap-1.5 items-center">
            <TypeChip type="Email headers" />
            <span className="text-xs text-fg-3">{ioc.trimmed.split('\n').length} lines</span>
          </div>
          <p className="text-xs text-fg-3 leading-relaxed">
            Run analysis to parse authentication results, trace the relay path and enrich the sending IP and From domain.
          </p>
          <div className="text-[11px] text-fg-4 font-mono space-y-0.5 border-t border-line pt-2">
            {ioc.trimmed.split('\n').slice(0, 5).map((line, i) => (
              <p key={i} className="truncate">{line}</p>
            ))}
          </div>
        </div>
      ) : (
        <>
          <div className="flex flex-wrap gap-1.5">
            <TypeChip type={ioc.type} />
            <ConfidenceChip confidence={ioc.confidence} />
          </div>

          <div className="flex items-start gap-2">
            <code className="flex-1 min-w-0 text-[13px] font-mono text-fg-1 break-all leading-snug">
              {displayValue}
            </code>
            <div className="flex items-center gap-1 shrink-0 -mt-0.5">
              <CopyButton text={ioc.normalised} label="value" iconOnly />
              {canDefang && (
                <button
                  onClick={() => setDefanged(v => !v)}
                  title={defanged ? 'Show live value' : 'Show defanged value'}
                  aria-pressed={defanged}
                  className={`inline-flex items-center justify-center h-7 px-1.5 rounded-md border transition-colors text-[11px] font-mono font-medium ${
                    defanged
                      ? 'border-accent-line bg-accent-bg text-accent-fg'
                      : 'border-line bg-surface text-fg-3 hover:border-line-strong hover:text-fg-1'
                  }`}
                >
                  [.]
                </button>
              )}
            </div>
          </div>

          <div className="space-y-0.5 border-t border-line pt-2.5">
            {ioc.original.trim() !== ioc.normalised && (
              <Field k="Input"><code className="font-mono text-fg-3 break-all">{ioc.original.trim()}</code></Field>
            )}
            {ioc.type === 'url' && ioc.urlExtract && (
              <>
                <Field k="Scheme"><code className="font-mono">{ioc.urlExtract.scheme}</code></Field>
                <Field k="Host"><code className="font-mono break-all">{ioc.urlExtract.hostname}</code></Field>
                <Field k="Domain"><code className="font-mono break-all">{ioc.urlExtract.domain}</code></Field>
                <Field k="Path"><code className="font-mono break-all">{ioc.urlExtract.path || '/'}</code></Field>
                {ioc.urlExtract.queryParamNames.length > 0 && (
                  <Field k="Params"><code className="font-mono break-all">{ioc.urlExtract.queryParamNames.join(', ')}</code></Field>
                )}
              </>
            )}
          </div>

          {ioc.isSensitiveUrl && (
            <div className="flex gap-2 p-2.5 rounded-md border bg-warn-bg border-warn-line text-xs text-warn-fg">
              <svg className="w-3.5 h-3.5 shrink-0 mt-0.5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0zM12 9v4m0 4h.01" />
              </svg>
              <span><strong className="font-semibold">Contains tokens or identifiers.</strong> Don’t submit to public tools; use internal tooling.</span>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── Main IocInput / Command bar ───────────────────────────────────────────

interface IocInputProps {
  onDetect: (ioc: DetectedIoc | null) => void;
  onReset: () => void;
  /** Called on Cmd/Ctrl+Enter */
  onSubmit?: () => void;
  prefillValue?: string;
  onPrefillConsumed?: () => void;
  /** Value to show on mount, so returning to the page keeps the current indicator */
  initialValue?: string;
}

export function IocInput({ onDetect, onReset, onSubmit, prefillValue, onPrefillConsumed, initialValue = '' }: IocInputProps) {
  const [value, setValue] = useState(initialValue);
  const [ioc, setIoc] = useState<DetectedIoc | null>(() => (initialValue.trim() ? detectIoc(initialValue) : null));
  const [history, setHistory] = useState<string[]>(() => loadHistory());
  const [showHistory, setShowHistory] = useState(false);
  const saveTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const valueRef = useRef(value);

  useEffect(() => { valueRef.current = value; });

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setShowHistory(false);
      }
    }
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  useEffect(() => {
    if (prefillValue !== undefined && prefillValue !== valueRef.current) {
      setValue(prefillValue);
      if (prefillValue.trim()) {
        const detected = detectIoc(prefillValue);
        setIoc(detected);
        onDetect(detected);
      } else {
        setIoc(null);
        onDetect(null);
      }
      // Tell App to clear prefillIoc so future re-renders don't re-fire this effect
      onPrefillConsumed?.();
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [prefillValue]);

  function scheduleHistorySave(detected: DetectedIoc | null, raw: string) {
    if (saveTimer.current) clearTimeout(saveTimer.current);
    if (!detected || detected.type === 'unknown') return;
    saveTimer.current = setTimeout(() => {
      addToHistory(raw.trim());
      setHistory(loadHistory());
    }, 900);
  }

  const handleChange = useCallback((e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const v = e.target.value;
    setValue(v);
    setShowHistory(false);
    if (!v.trim()) {
      setIoc(null);
      onDetect(null);
      scheduleHistorySave(null, v);
    } else {
      const detected = detectIoc(v);
      setIoc(detected);
      onDetect(detected);
      scheduleHistorySave(detected, v);
    }
  }, [onDetect]);

  const handleReset = () => {
    setValue('');
    setIoc(null);
    onDetect(null);
    onReset();
    setShowHistory(false);
    if (saveTimer.current) clearTimeout(saveTimer.current);
  };

  const handlePaste = useCallback((e: React.ClipboardEvent<HTMLTextAreaElement>) => {
    const pasted = normalizeIocInput(e.clipboardData.getData('text'));
    const el = e.target as HTMLTextAreaElement;
    const start = el.selectionStart ?? el.value.length;
    const end = el.selectionEnd ?? el.value.length;
    const newValue = el.value.slice(0, start) + pasted + el.value.slice(end);
    e.preventDefault();
    setValue(newValue);
    setShowHistory(false);
    if (newValue.trim()) {
      const detected = detectIoc(newValue);
      setIoc(detected);
      onDetect(detected);
      scheduleHistorySave(detected, newValue);
    } else {
      setIoc(null);
      onDetect(null);
    }
  }, [onDetect]);

  function handleHistorySelect(item: string) {
    setValue(item);
    const detected = detectIoc(item);
    setIoc(detected);
    onDetect(detected);
    setShowHistory(false);
  }

  function handleClearHistory() {
    clearRecentIndicators();
    setHistory([]);
    setShowHistory(false);
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      onSubmit?.();
    } else if (e.key === 'Escape' && value) {
      e.preventDefault();
      handleReset();
    }
  }

  return (
    <div className="wb-card flex flex-col lg:flex-row overflow-hidden">
      <div className="flex-1 min-w-0 p-4 flex flex-col gap-2.5 justify-start">
        <div className="flex items-center justify-between h-7">
          <label htmlFor="ioc-input" className="wb-label">Indicator</label>
          <div className="flex items-center gap-1.5">
            {history.length > 0 && (
              <div className="relative" ref={dropdownRef}>
                <button
                  onClick={() => setShowHistory(v => !v)}
                  aria-expanded={showHistory}
                  className={`inline-flex items-center gap-1.5 text-xs h-7 px-2 rounded-md transition-colors ${
                    showHistory ? 'bg-raised text-fg-1' : 'text-fg-3 hover:text-fg-1 hover:bg-raised'
                  }`}
                >
                  <IconClock />
                  Recent
                </button>

                {showHistory && (
                  <div className="absolute right-0 top-full mt-1 z-50 w-80 bg-surface border border-line rounded-lg shadow-lg overflow-hidden">
                    <div className="flex items-center justify-between px-3 py-2 border-b border-line-soft">
                      <span className="text-xs font-medium text-fg-2">Recent indicators</span>
                      <button onClick={handleClearHistory} className="text-xs text-fg-4 hover:text-danger-fg transition-colors">
                        Clear
                      </button>
                    </div>
                    <ul className="py-1">
                      {history.map((item, i) => {
                        const detected = detectIoc(item);
                        return (
                          <li key={i}>
                            <button
                              onClick={() => handleHistorySelect(item)}
                              className="w-full flex items-center gap-3 px-3 py-1.5 text-left hover:bg-inset transition-colors"
                            >
                              <span className="shrink-0 w-14 text-[10px] font-mono font-medium text-fg-4 uppercase">
                                {detected.type === 'unknown' ? '—' : TYPE_LABELS[detected.type] ?? detected.type}
                              </span>
                              <span className="flex-1 min-w-0 text-xs font-mono text-fg-1 truncate">{item}</span>
                            </button>
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                )}
              </div>
            )}

            {value && (
              <button
                onClick={handleReset}
                className="inline-flex items-center gap-1.5 text-xs h-7 px-2 rounded-md text-fg-3 hover:text-fg-1 hover:bg-raised transition-colors"
              >
                <IconX />
                Clear
              </button>
            )}
          </div>
        </div>

        <textarea
          id="ioc-input"
          value={value}
          onChange={handleChange}
          onPaste={handlePaste}
          onKeyDown={handleKeyDown}
          rows={3}
          placeholder="Paste an indicator — IP, domain, URL, hash, email, ASN, CIDR — or raw email headers"
          className="w-full min-h-[96px] bg-surface border border-line-strong rounded-md px-3 py-2.5 text-[15px] font-mono text-fg-1 focus:outline-none focus:border-accent focus:ring-[3px] focus:ring-accent/15 resize-y transition-[border-color,box-shadow] leading-relaxed"
          spellCheck={false}
          autoComplete="off"
          autoCapitalize="off"
          autoCorrect="off"
        />

        {!value && (
          <div className="flex flex-wrap items-center gap-1.5 text-xs text-fg-4">
            <span>Try a sample:</span>
            {SAMPLES.map(sample => (
              <button
                key={sample.value}
                onClick={() => handleHistorySelect(sample.value)}
                title={sample.note}
                className="h-6 px-2 rounded border border-line bg-surface font-mono text-[11px] text-fg-2 hover:border-accent hover:text-accent-fg"
              >
                {sample.value}
              </button>
            ))}
          </div>
        )}

        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-fg-4">
          <span className="inline-flex items-center gap-1.5"><span className="kbd">⌘</span><span className="kbd">↵</span> run analysis</span>
          <span className="inline-flex items-center gap-1.5"><span className="kbd">/</span> focus</span>
          <span className="inline-flex items-center gap-1.5"><span className="kbd">esc</span> clear</span>
          <span className="ml-auto">Defanged input (hxxp, [.]) is refanged automatically</span>
        </div>
      </div>

      <ClassificationCard ioc={ioc} />
    </div>
  );
}
