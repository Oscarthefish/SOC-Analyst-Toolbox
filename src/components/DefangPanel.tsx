import { useState, useCallback } from 'react';
import { processDefang, type DefangResult } from '../lib/defang';
import { CopyButton } from './CopyButton';
import { IocTypeChip } from './IocTypeChip';

/** Marks the parts defanging changes ([.], [@], [:], hxxp) so the transform is visible. */
function Marked({ text }: { text: string }) {
  const parts = text.split(/(\[\.\]|\[@\]|\[:\]|hxxps?)/g);
  return (
    <>
      {parts.map((p, i) => /^(\[\.\]|\[@\]|\[:\]|hxxps?)$/.test(p)
        ? <mark key={i} className="bg-warn-bg text-warn-fg rounded-sm px-px ring-1 ring-warn-line">{p}</mark>
        : <span key={i}>{p}</span>)}
    </>
  );
}

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
            <IocTypeChip type={result.type === 'other' ? 'unknown' : result.type} />
          </div>

          <div className="space-y-3">
            <div className="flex items-center gap-3 p-3 rounded-lg bg-inset border border-line">
              <div className="flex-1 min-w-0">
                <p className="wb-label mb-1">Original input</p>
                <code className="text-[14px] font-mono text-fg-2 break-all">{result.original}</code>
              </div>
              <CopyButton text={result.original} iconOnly />
            </div>

            <div className="flex items-center gap-3 p-3 rounded-lg bg-surface border border-line border-l-[3px] border-l-warn">
              <div className="flex-1 min-w-0">
                <p className="text-[11px] font-semibold uppercase tracking-wider text-warn-fg mb-1">
                  Defanged <span className="font-normal normal-case text-fg-3 tracking-normal">· safe to share in tickets &amp; reports</span>
                </p>
                <code className="text-[14px] font-mono text-fg-1 break-all"><Marked text={result.defanged} /></code>
              </div>
              <CopyButton text={result.defanged} iconOnly />
            </div>

            <div className="flex items-center gap-3 p-3 rounded-lg bg-surface border border-line border-l-[3px] border-l-danger">
              <div className="flex-1 min-w-0">
                <p className="text-[11px] font-semibold uppercase tracking-wider text-danger-fg mb-1">
                  Refanged <span className="font-normal normal-case text-fg-3 tracking-normal">· live, clickable form — handle with care</span>
                </p>
                <code className="text-[14px] font-mono text-fg-1 break-all">{result.refanged}</code>
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

      <div className="wb-card overflow-hidden">
        <p className="wb-label px-5 pt-4 pb-3">Defang reference</p>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-inset border-y border-line text-[11px] text-fg-4">
                <th className="text-left font-normal px-5 py-2">Type</th>
                <th className="text-left font-normal px-3 py-2">Live</th>
                <th className="text-left font-normal px-3 py-2">Defanged</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line-soft">
              {[
                { type: 'ipv4',   fanged: '1.2.3.4',               defanged: '1[.]2[.]3[.]4' },
                { type: 'domain', fanged: 'example.com',            defanged: 'example[.]com' },
                { type: 'url',    fanged: 'https://example.com/p',  defanged: 'hxxps://example[.]com/p' },
                { type: 'url',    fanged: 'http://example.com/p',   defanged: 'hxxp://example[.]com/p' },
                { type: 'email',  fanged: 'user@example.com',       defanged: 'user[@]example[.]com' },
              ].map(row => (
                <tr key={row.fanged}>
                  <td className="px-5 py-2"><IocTypeChip type={row.type} size="sm" /></td>
                  <td className="px-3 py-2"><code className="font-mono text-fg-2">{row.fanged}</code></td>
                  <td className="px-3 py-2"><code className="font-mono text-fg-1"><Marked text={row.defanged} /></code></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
