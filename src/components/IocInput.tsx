import { useState, useCallback, useEffect, useRef } from 'react';
import type { DetectedIoc } from '../types/ioc';
import { detectIoc } from '../lib/detectIoc';
import { defangUrlSmart, defangIp, defangDomain } from '../lib/defang';
import { CopyButton } from './CopyButton';

const HISTORY_KEY = 'soc-toolbox-ioc-history';
const MAX_HISTORY = 10;

function loadHistory(): string[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    return raw ? (JSON.parse(raw) as string[]) : [];
  } catch { return []; }
}

function addToHistory(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return;
  const prev = loadHistory();
  const next = [trimmed, ...prev.filter(h => h !== trimmed)].slice(0, MAX_HISTORY);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
}

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
  const isUnknown = type === 'unknown';
  return (
    <span className={`inline-flex items-center h-6 px-2.5 rounded-full text-xs font-semibold font-mono border ${
      isUnknown
        ? 'bg-[#fef3f2] border-[#fecdca] text-[#b42318]'
        : 'bg-[#eff8ff] border-[#b2ddff] text-[#175cd3]'
    }`}>
      {TYPE_LABELS[type] ?? type}
    </span>
  );
}

function ConfidenceChip({ confidence }: { confidence: 'high' | 'medium' | 'low' }) {
  const map = {
    high:   { cls: 'bg-[#ecfdf3] border-[#abefc6] text-[#067647]', dot: 'bg-[#079455]', label: 'High confidence' },
    medium: { cls: 'bg-[#fffaeb] border-[#fedf89] text-[#b54708]', dot: 'bg-[#dc6803]', label: 'Medium confidence' },
    low:    { cls: 'bg-[#fef3f2] border-[#fecdca] text-[#b42318]', dot: 'bg-[#d92d20]', label: 'Low confidence' },
  };
  const s = map[confidence];
  return (
    <span className={`inline-flex items-center gap-1.5 h-6 px-2.5 rounded-full text-xs font-medium border ${s.cls}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
      {s.label}
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

// ── Classification card ────────────────────────────────────────────────────

function ClassificationCard({ ioc }: { ioc: DetectedIoc | null }) {
  const [defanged, setDefanged] = useState(false);

  useEffect(() => { setDefanged(false); }, [ioc?.normalised]);

  const canDefang = ioc && ['url', 'ipv4', 'ipv6', 'domain', 'cidr', 'email'].includes(ioc.type);
  const displayValue = ioc && defanged ? defangValue(ioc) : (ioc?.normalised ?? '');

  return (
    <div className="w-[392px] shrink-0 bg-[#fafbfc] border border-[#e4e7ec] rounded-[10px] p-4 flex flex-col gap-3">
      <p className="wb-label">Classification</p>

      {!ioc || (ioc.type === 'unknown' && !ioc.isEmailHeader) ? (
        <div className="flex-1 flex items-center justify-center py-8">
          <p className="text-sm text-[#98a2b3] text-center leading-relaxed">
            Paste an IOC in the input<br />to classify it automatically.
          </p>
        </div>
      ) : ioc.isEmailHeader ? (
        <div className="space-y-3">
          <div className="flex flex-wrap gap-2 items-center">
            <span className="inline-flex items-center gap-1.5 h-6 px-2.5 rounded-full text-xs font-semibold border bg-[#eff8ff] border-[#b2ddff] text-[#175cd3]">
              <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
              </svg>
              Email Header
            </span>
            <span className="inline-flex items-center gap-1.5 h-6 px-2.5 rounded-full text-xs font-medium border bg-[#ecfdf3] border-[#abefc6] text-[#067647]">
              <span className="w-1.5 h-1.5 rounded-full bg-[#079455]" />
              Detected
            </span>
          </div>
          <div className="bg-white border border-[#e4e7ec] rounded-lg p-2.5">
            <p className="text-xs text-[#667085] leading-relaxed">
              Email header block detected. Select <strong className="text-[#344054]">Email Header Review</strong> in the workflow grid to open header analysis tools.
            </p>
          </div>
          <div className="text-xs text-[#98a2b3] space-y-0.5">
            {ioc.trimmed.split('\n').slice(0, 6).map((line, i) => (
              <p key={i} className="font-mono truncate">{line}</p>
            ))}
            {ioc.trimmed.split('\n').length > 6 && (
              <p className="text-[#d0d5dd]">+ {ioc.trimmed.split('\n').length - 6} more lines</p>
            )}
          </div>
        </div>
      ) : (
        <>
          {/* Type + confidence */}
          <div className="flex flex-wrap gap-2">
            <TypeChip type={ioc.type} />
            <ConfidenceChip confidence={ioc.confidence} />
          </div>

          {/* Value display with actions */}
          <div className="bg-white border border-[#e4e7ec] rounded-lg p-2.5 space-y-1.5">
            <div className="flex items-start justify-between gap-2">
              <code className="text-[13px] font-mono text-[#101828] break-all leading-snug flex-1">
                {displayValue}
              </code>
              <div className="flex items-center gap-1 shrink-0">
                <CopyButton text={ioc.normalised} label="value" iconOnly />
                {canDefang && (
                  <button
                    onClick={() => setDefanged(v => !v)}
                    title={defanged ? 'Show original' : 'Defang IOC'}
                    className={`inline-flex items-center justify-center w-7 h-7 rounded-lg border transition-colors text-xs font-mono font-semibold ${
                      defanged
                        ? 'border-[#b2ddff] bg-[#eff8ff] text-[#175cd3]'
                        : 'border-[#e4e7ec] bg-white text-[#667085] hover:border-[#d0d5dd]'
                    }`}
                  >
                    {defanged ? '🔓' : '[.]'}
                  </button>
                )}
              </div>
            </div>

            {/* Show original if different from normalised */}
            {ioc.original.trim() !== ioc.normalised && (
              <div className="flex items-center gap-1.5 pt-1 border-t border-[#f2f4f7]">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-[#98a2b3]">Original</span>
                <code className="text-[11px] font-mono text-[#98a2b3] truncate">{ioc.original.trim()}</code>
              </div>
            )}
          </div>

          {/* URL breakdown */}
          {ioc.type === 'url' && ioc.urlExtract && (
            <div className="space-y-1">
              <p className="wb-label">URL Breakdown</p>
              <div className="space-y-0.5">
                {[
                  { k: 'Scheme',   v: ioc.urlExtract.scheme },
                  { k: 'Host',     v: ioc.urlExtract.hostname },
                  { k: 'Domain',   v: ioc.urlExtract.domain },
                  { k: 'Path',     v: ioc.urlExtract.path || '/' },
                  ioc.urlExtract.query ? { k: 'Query', v: ioc.urlExtract.query } : null,
                  ioc.urlExtract.queryParamNames.length ? { k: 'Params', v: ioc.urlExtract.queryParamNames.join(', ') } : null,
                ].filter(Boolean).map(row => (
                  <div key={row!.k} className="flex gap-2 text-xs">
                    <span className="w-12 shrink-0 text-[#98a2b3] font-medium">{row!.k}</span>
                    <code className="text-[#475467] font-mono break-all">{row!.v}</code>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Sensitive URL warning */}
          {ioc.isSensitiveUrl && (
            <div className="flex gap-2 p-2.5 rounded-lg border bg-[#fffaeb] border-[#fedf89] text-xs text-[#b54708]">
              <svg className="w-3.5 h-3.5 shrink-0 mt-0.5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0zM12 9v4m0 4h.01" />
              </svg>
              <span><strong>Sensitive URL</strong> — avoid public submission. Use internal tooling.</span>
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
  prefillValue?: string;
}

export function IocInput({ onDetect, onReset, prefillValue }: IocInputProps) {
  const [value, setValue] = useState('');
  const [ioc, setIoc] = useState<DetectedIoc | null>(null);
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
  // eslint-disable-next-line react-hooks/exhaustive-deps
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
    const pasted = e.clipboardData.getData('text');
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
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [onDetect]);

  function handleHistorySelect(item: string) {
    setValue(item);
    const detected = detectIoc(item);
    setIoc(detected);
    onDetect(detected);
    setShowHistory(false);
  }

  function handleClearHistory() {
    localStorage.removeItem(HISTORY_KEY);
    setHistory([]);
    setShowHistory(false);
  }

  return (
    <div className="wb-card p-5">
      <div className="flex gap-5 items-start">
        {/* Left: indicator input */}
        <div className="flex-1 min-w-0 space-y-3">
          <div className="flex items-center justify-between">
            <p className="wb-label">Indicator</p>
            <div className="flex items-center gap-2">
              {/* Recent dropdown */}
              {history.length > 0 && (
                <div className="relative" ref={dropdownRef}>
                  <button
                    onClick={() => setShowHistory(v => !v)}
                    className={`inline-flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-lg border transition-colors font-medium ${
                      showHistory
                        ? 'border-[#b2ddff] bg-[#eff8ff] text-[#175cd3]'
                        : 'border-[#e4e7ec] bg-white text-[#475467] hover:border-[#d0d5dd]'
                    }`}
                  >
                    <IconClock />
                    Recent
                  </button>

                  {showHistory && (
                    <div className="absolute right-0 top-full mt-1.5 z-50 w-80 bg-white border border-[#e4e7ec] rounded-xl shadow-lg overflow-hidden">
                      <div className="flex items-center justify-between px-3 py-2 border-b border-[#f2f4f7]">
                        <span className="wb-label">Recent searches</span>
                        <button
                          onClick={handleClearHistory}
                          className="text-xs text-[#98a2b3] hover:text-[#d92d20] transition-colors"
                        >
                          Clear all
                        </button>
                      </div>
                      <ul>
                        {history.map((item, i) => {
                          const detected = detectIoc(item);
                          return (
                            <li key={i}>
                              <button
                                onClick={() => handleHistorySelect(item)}
                                className="w-full flex items-center gap-3 px-3 py-2 text-left hover:bg-[#f9fafb] transition-colors group"
                              >
                                <span className="shrink-0 text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded-md bg-[#f2f4f7] text-[#667085] border border-[#e4e7ec] uppercase w-14 text-center">
                                  {detected.type === 'unknown' ? '?' : TYPE_LABELS[detected.type] ?? detected.type}
                                </span>
                                <span className="flex-1 min-w-0 text-xs font-mono text-[#344054] truncate">
                                  {item}
                                </span>
                              </button>
                            </li>
                          );
                        })}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {/* Reset */}
              {value && (
                <button
                  onClick={handleReset}
                  className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-lg border border-[#e4e7ec] bg-white text-[#475467] hover:border-[#fecdca] hover:text-[#b42318] transition-colors font-medium"
                >
                  <IconX />
                  Reset
                </button>
              )}
            </div>
          </div>

          <textarea
            value={value}
            onChange={handleChange}
            onPaste={handlePaste}
            rows={4}
            placeholder="Paste an IP, domain, URL, hash, email, ASN or CIDR…"
            className="w-full bg-[#fafbfc] border border-[#e4e7ec] rounded-lg px-3.5 py-3 text-[17px] font-mono text-[#101828] placeholder-[#98a2b3] focus:outline-none focus:border-[#1570ef] focus:ring-2 focus:ring-[#1570ef]/20 resize-none transition-colors leading-snug"
            spellCheck={false}
            autoComplete="off"
            autoCapitalize="off"
            autoCorrect="off"
          />

          <p className="text-xs text-[#98a2b3]">
            Supports: IPv4 · IPv6 · Domain · URL · MD5 · SHA-1 · SHA-256 · Email · ASN · CIDR
          </p>
        </div>

        {/* Right: classification card */}
        <ClassificationCard ioc={ioc} />
      </div>
    </div>
  );
}
