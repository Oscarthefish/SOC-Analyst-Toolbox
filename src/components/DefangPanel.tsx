import { useState, useCallback } from 'react';
import { processDefang, type DefangResult } from '../lib/defang';
import { CopyButton } from './CopyButton';

const TYPE_LABELS: Record<string, string> = {
  ipv4: 'IPv4', ipv6: 'IPv6', domain: 'Domain', url: 'URL',
  email: 'Email', cidr: 'CIDR', other: 'Unknown',
};

export function DefangPanel() {
  const [input, setInput] = useState('');
  const [result, setResult] = useState<DefangResult | null>(null);

  const handleChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value;
    setInput(val);
    setResult(val.trim() ? processDefang(val.trim()) : null);
  }, []);

  const handleSample = useCallback((sample: string) => {
    setInput(sample);
    setResult(processDefang(sample));
  }, []);

  return (
    <div className="space-y-4">
      <div className="wb-card p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <p className="wb-label">Defang / Refang</p>
            <p className="text-xs text-fg-4 mt-0.5">Convert IOCs between live and safe-for-sharing formats</p>
          </div>
          {input && (
            <button onClick={() => { setInput(''); setResult(null); }}
              className="text-xs text-fg-3 hover:text-danger-fg transition-colors flex items-center gap-1 font-medium">
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M18 6L6 18M6 6l12 12" />
              </svg>
              Clear
            </button>
          )}
        </div>

        <input
          type="text"
          value={input}
          onChange={handleChange}
          placeholder="Paste an IP, domain, URL, or defanged IOC (e.g. 1[.]2[.]3[.]4 or hxxps://evil[.]com)…"
          className="w-full bg-inset border border-line rounded-lg px-3.5 py-3 text-[15px] font-mono text-fg-1 placeholder-fg-4 focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition-colors"
          spellCheck={false}
          autoComplete="off"
        />

        <div className="mt-3 flex flex-wrap gap-2 items-center">
          <span className="text-xs text-fg-4">Try:</span>
          {['1.2.3.4', 'example.com', 'https://evil.example.com/path', 'user@example.com', '1[.]2[.]3[.]4', 'hxxps://evil[.]example[.]com'].map(s => (
            <button key={s} onClick={() => handleSample(s)}
              className="text-xs px-2 py-1 rounded-lg border border-line bg-surface text-fg-3 hover:border-line-strong font-mono transition-colors">
              {s}
            </button>
          ))}
        </div>
      </div>

      {result && (
        <div className="wb-card p-5">
          <div className="flex items-center gap-2 mb-4">
            <p className="wb-label">Detected type</p>
            <span className="inline-flex items-center h-6 px-2.5 rounded text-xs font-semibold font-mono bg-accent-bg border border-accent-line text-accent-fg">
              {TYPE_LABELS[result.type] ?? result.type}
            </span>
          </div>

          <div className="space-y-3">
            <div className="flex items-center gap-3 p-3 rounded-lg bg-inset border border-line">
              <div className="flex-1 min-w-0">
                <p className="wb-label mb-1">Original input</p>
                <code className="text-[14px] font-mono text-fg-2 break-all">{result.original}</code>
              </div>
              <CopyButton text={result.original} iconOnly />
            </div>

            <div className="flex items-center gap-3 p-3 rounded-lg bg-warn-bg border border-warn-line">
              <div className="flex-1 min-w-0">
                <p className="text-[11px] font-bold uppercase tracking-wider text-warn-fg mb-1">
                  Defanged <span className="font-normal normal-case text-warn-fg/60 tracking-normal">· safe to share in tickets &amp; reports</span>
                </p>
                <code className="text-[14px] font-mono text-warn-fg break-all">{result.defanged}</code>
              </div>
              <CopyButton text={result.defanged} iconOnly />
            </div>

            <div className="flex items-center gap-3 p-3 rounded-lg bg-ok-bg border border-ok-line">
              <div className="flex-1 min-w-0">
                <p className="text-[11px] font-bold uppercase tracking-wider text-ok-fg mb-1">
                  Refanged <span className="font-normal normal-case text-ok-fg/60 tracking-normal">· live / clickable form</span>
                </p>
                <code className="text-[14px] font-mono text-ok-fg break-all">{result.refanged}</code>
              </div>
              <CopyButton text={result.refanged} iconOnly />
            </div>
          </div>

          {result.type === 'other' && (
            <p className="mt-3 text-xs text-fg-4">
              Type not fully recognised — showing input as-is. Supported: IPv4, domain, URL, email, CIDR.
            </p>
          )}
        </div>
      )}

      <div className="wb-card p-5">
        <p className="wb-label mb-4">Defang Reference</p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[
            { label: 'IP address',  fanged: '1.2.3.4',              defanged: '1[.]2[.]3[.]4' },
            { label: 'Domain',      fanged: 'example.com',           defanged: 'example[.]com' },
            { label: 'HTTPS URL',   fanged: 'https://example.com/p', defanged: 'hxxps://example[.]com/p' },
            { label: 'HTTP URL',    fanged: 'http://example.com/p',  defanged: 'hxxp://example[.]com/p' },
          ].map(row => (
            <div key={row.label} className="flex items-start gap-3 text-xs">
              <span className="text-fg-4 w-20 shrink-0 font-medium">{row.label}</span>
              <div className="space-y-1">
                <code className="block text-fg-2 font-mono">{row.fanged}</code>
                <span className="block text-fg-4">↓</span>
                <code className="block text-warn-fg font-mono">{row.defanged}</code>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
