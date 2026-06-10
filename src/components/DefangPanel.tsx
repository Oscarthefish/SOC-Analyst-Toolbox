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
            <p className="text-xs text-[#98a2b3] mt-0.5">Convert IOCs between live and safe-for-sharing formats</p>
          </div>
          {input && (
            <button onClick={() => { setInput(''); setResult(null); }}
              className="text-xs text-[#667085] hover:text-[#b42318] transition-colors flex items-center gap-1 font-medium">
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
          className="w-full bg-[#fafbfc] border border-[#e4e7ec] rounded-lg px-3.5 py-3 text-[15px] font-mono text-[#101828] placeholder-[#98a2b3] focus:outline-none focus:border-[#1570ef] focus:ring-2 focus:ring-[#1570ef]/20 transition-colors"
          spellCheck={false}
          autoComplete="off"
        />

        <div className="mt-3 flex flex-wrap gap-2 items-center">
          <span className="text-xs text-[#98a2b3]">Try:</span>
          {['1.2.3.4', 'example.com', 'https://evil.example.com/path', 'user@example.com', '1[.]2[.]3[.]4', 'hxxps://evil[.]example[.]com'].map(s => (
            <button key={s} onClick={() => handleSample(s)}
              className="text-xs px-2 py-1 rounded-lg border border-[#e4e7ec] bg-white text-[#667085] hover:border-[#d0d5dd] font-mono transition-colors">
              {s}
            </button>
          ))}
        </div>
      </div>

      {result && (
        <div className="wb-card p-5">
          <div className="flex items-center gap-2 mb-4">
            <p className="wb-label">Detected type</p>
            <span className="inline-flex items-center h-6 px-2.5 rounded-full text-xs font-semibold font-mono bg-[#eff8ff] border border-[#b2ddff] text-[#175cd3]">
              {TYPE_LABELS[result.type] ?? result.type}
            </span>
          </div>

          <div className="space-y-3">
            <div className="flex items-center gap-3 p-3 rounded-lg bg-[#fafbfc] border border-[#e4e7ec]">
              <div className="flex-1 min-w-0">
                <p className="wb-label mb-1">Original input</p>
                <code className="text-[14px] font-mono text-[#344054] break-all">{result.original}</code>
              </div>
              <CopyButton text={result.original} iconOnly />
            </div>

            <div className="flex items-center gap-3 p-3 rounded-lg bg-[#fffaeb] border border-[#fedf89]">
              <div className="flex-1 min-w-0">
                <p className="text-[11px] font-bold uppercase tracking-wider text-[#b54708] mb-1">
                  Defanged <span className="font-normal normal-case text-[#b54708]/60 tracking-normal">· safe to share in tickets &amp; reports</span>
                </p>
                <code className="text-[14px] font-mono text-[#b54708] break-all">{result.defanged}</code>
              </div>
              <CopyButton text={result.defanged} iconOnly />
            </div>

            <div className="flex items-center gap-3 p-3 rounded-lg bg-[#ecfdf3] border border-[#abefc6]">
              <div className="flex-1 min-w-0">
                <p className="text-[11px] font-bold uppercase tracking-wider text-[#067647] mb-1">
                  Refanged <span className="font-normal normal-case text-[#067647]/60 tracking-normal">· live / clickable form</span>
                </p>
                <code className="text-[14px] font-mono text-[#067647] break-all">{result.refanged}</code>
              </div>
              <CopyButton text={result.refanged} iconOnly />
            </div>
          </div>

          {result.type === 'other' && (
            <p className="mt-3 text-xs text-[#98a2b3]">
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
              <span className="text-[#98a2b3] w-20 shrink-0 font-medium">{row.label}</span>
              <div className="space-y-1">
                <code className="block text-[#344054] font-mono">{row.fanged}</code>
                <span className="block text-[#98a2b3]">↓</span>
                <code className="block text-[#b54708] font-mono">{row.defanged}</code>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
