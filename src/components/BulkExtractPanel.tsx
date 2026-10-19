import { useState, useCallback } from 'react';
import { extractIocs, type ExtractedIoc } from '../lib/extractIocs';
import { CopyButton } from './CopyButton';
import type { IocType } from '../types/ioc';

interface BulkExtractPanelProps {
  onInvestigate: (ioc: string) => void;
}

const TYPE_LABELS: Record<IocType, string> = {
  ipv4: 'IPv4', ipv6: 'IPv6', domain: 'Domain', url: 'URL',
  md5: 'MD5', sha1: 'SHA-1', sha256: 'SHA-256', email: 'Email',
  asn: 'ASN', cidr: 'CIDR', cve: 'CVE', secret: 'Secret / Credential', unknown: 'Unknown',
};

const SAMPLE_TEXT = `Firewall alert - blocked connection attempt
src=192.168.1.45 dst=185.220.101.42 proto=TCP dport=443 action=drop
domain: malicious-site.ru contacted from host DESKTOP-ABC123
SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
user: john.doe@company.com received phishing email from support@evil-phishing.com
URL observed: https://login.evil-phishing.com/reset?token=abc123
ASN: AS15169 (Google LLC) - this one is benign
Also seen: 10.0.0.0/8 internal CIDR`;

export function BulkExtractPanel({ onInvestigate }: BulkExtractPanelProps) {
  const [text, setText] = useState('');
  const [results, setResults] = useState<ExtractedIoc[]>([]);
  const [filter, setFilter] = useState<IocType | 'all'>('all');
  const [hasRun, setHasRun] = useState(false);

  const handleExtract = useCallback(() => {
    if (!text.trim()) return;
    setResults(extractIocs(text));
    setHasRun(true);
  }, [text]);

  const handleClear = useCallback(() => {
    setText(''); setResults([]); setHasRun(false); setFilter('all');
  }, []);

  const filteredResults = filter === 'all' ? results : results.filter(r => r.type === filter);
  const typeCounts = results.reduce<Partial<Record<IocType, number>>>((acc, r) => {
    acc[r.type] = (acc[r.type] ?? 0) + 1; return acc;
  }, {});
  const uniqueTypes = [...new Set(results.map(r => r.type))];
  const allIocsText = results.map(r => r.normalised).join('\n');
  const allIocsCsv  = results.map(r => `${r.type},${r.normalised}`).join('\n');

  return (
    <div className="space-y-4">
      <div className="wb-card p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <p className="wb-label">Bulk IOC Extractor</p>
            <p className="text-xs text-fg-4 mt-0.5">Paste logs, email headers, EDR alerts, or any text</p>
          </div>
          <div className="flex gap-2">
            <button onClick={() => { setText(SAMPLE_TEXT); setResults([]); setHasRun(false); }}
              className="text-xs px-2.5 py-1.5 rounded-lg border border-line bg-surface text-fg-2 hover:border-line-strong transition-colors font-medium">
              Load sample
            </button>
            {text && (
              <button onClick={handleClear}
                className="text-xs px-2.5 py-1.5 rounded-lg border border-line bg-surface text-fg-2 hover:border-danger-line hover:text-danger-fg transition-colors font-medium">
                Clear
              </button>
            )}
          </div>
        </div>

        <textarea
          value={text}
          onChange={e => setText(e.target.value)}
          rows={8}
          placeholder="Paste logs, email headers, firewall output, EDR alerts, or any text containing IOCs…"
          className="w-full bg-inset border border-line rounded-lg px-3.5 py-3 text-sm font-mono text-fg-1 placeholder-fg-4 focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 resize-y transition-colors"
          spellCheck={false}
        />

        <div className="mt-3 flex items-center gap-3">
          <button onClick={handleExtract} disabled={!text.trim()}
            className="px-4 py-2 text-sm font-semibold rounded-lg bg-accent text-white hover:bg-accent-strong transition-colors disabled:opacity-40 disabled:cursor-not-allowed">
            Extract IOCs
          </button>
          {hasRun && (
            <span className="text-sm text-fg-3">
              Found <strong className="text-fg-1">{results.length}</strong> unique IOC{results.length !== 1 ? 's' : ''}
            </span>
          )}
        </div>
      </div>

      {hasRun && results.length === 0 && (
        <div className="wb-card p-8 text-center">
          <p className="text-sm text-fg-3">No IOCs found in the provided text.</p>
          <p className="text-xs text-fg-4 mt-1">Try pasting logs or text containing IPs, domains, URLs, or file hashes.</p>
        </div>
      )}

      {results.length > 0 && (
        <div className="wb-card p-5">
          <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
            <div className="flex flex-wrap gap-1.5">
              {(['all', ...uniqueTypes] as (IocType | 'all')[]).map(t => (
                <button key={t} onClick={() => setFilter(t)}
                  className={`text-xs px-2.5 py-1 rounded-lg border font-medium transition-colors ${
                    filter === t
                      ? 'bg-accent-bg border-accent-line text-accent-fg'
                      : 'bg-surface border-line text-fg-3 hover:border-line-strong'
                  }`}>
                  {t === 'all' ? `All (${results.length})` : `${TYPE_LABELS[t]} (${typeCounts[t] ?? 0})`}
                </button>
              ))}
            </div>
            <div className="flex gap-2">
              <CopyButton text={allIocsText} label="all IOCs" />
              <CopyButton text={allIocsCsv} label="CSV" />
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-line-soft">
                  <th className="text-left py-2 px-2 wb-label w-20">Type</th>
                  <th className="text-left py-2 px-2 wb-label">IOC</th>
                  <th className="text-left py-2 px-2 wb-label hidden md:table-cell">Normalised</th>
                  <th className="text-right py-2 px-2 wb-label w-36">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-inset">
                {filteredResults.map((ioc, i) => (
                  <tr key={i} className="hover:bg-inset transition-colors">
                    <td className="py-2 px-2">
                      <span className="inline-flex items-center h-5 px-2 rounded-md bg-accent-bg border border-accent-line text-accent-fg text-[11px] font-semibold font-mono">
                        {TYPE_LABELS[ioc.type]}
                      </span>
                    </td>
                    <td className="py-2 px-2">
                      <code className="text-[13px] font-mono text-fg-2 break-all">{ioc.raw}</code>
                    </td>
                    <td className="py-2 px-2 hidden md:table-cell">
                      {ioc.normalised !== ioc.raw
                        ? <code className="text-xs font-mono text-fg-3 break-all">{ioc.normalised}</code>
                        : <span className="text-fg-4">—</span>}
                    </td>
                    <td className="py-2 px-2 text-right">
                      <div className="flex gap-1.5 justify-end">
                        <CopyButton text={ioc.normalised} label="Copy" />
                        <button onClick={() => onInvestigate(ioc.normalised)}
                          className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-semibold rounded-lg bg-accent text-white hover:bg-accent-strong transition-colors">
                          <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
                            <circle cx="11" cy="11" r="8" /><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35" />
                          </svg>
                          Investigate
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
