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
  asn: 'ASN', cidr: 'CIDR', cve: 'CVE', unknown: 'Unknown',
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
            <p className="text-xs text-[#98a2b3] mt-0.5">Paste logs, email headers, EDR alerts, or any text</p>
          </div>
          <div className="flex gap-2">
            <button onClick={() => { setText(SAMPLE_TEXT); setResults([]); setHasRun(false); }}
              className="text-xs px-2.5 py-1.5 rounded-lg border border-[#e4e7ec] bg-white text-[#475467] hover:border-[#d0d5dd] transition-colors font-medium">
              Load sample
            </button>
            {text && (
              <button onClick={handleClear}
                className="text-xs px-2.5 py-1.5 rounded-lg border border-[#e4e7ec] bg-white text-[#475467] hover:border-[#fecdca] hover:text-[#b42318] transition-colors font-medium">
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
          className="w-full bg-[#fafbfc] border border-[#e4e7ec] rounded-lg px-3.5 py-3 text-sm font-mono text-[#101828] placeholder-[#98a2b3] focus:outline-none focus:border-[#1570ef] focus:ring-2 focus:ring-[#1570ef]/20 resize-y transition-colors"
          spellCheck={false}
        />

        <div className="mt-3 flex items-center gap-3">
          <button onClick={handleExtract} disabled={!text.trim()}
            className="px-4 py-2 text-sm font-semibold rounded-lg bg-[#1570ef] text-white hover:bg-[#175cd3] transition-colors disabled:opacity-40 disabled:cursor-not-allowed">
            Extract IOCs
          </button>
          {hasRun && (
            <span className="text-sm text-[#667085]">
              Found <strong className="text-[#101828]">{results.length}</strong> unique IOC{results.length !== 1 ? 's' : ''}
            </span>
          )}
        </div>
      </div>

      {hasRun && results.length === 0 && (
        <div className="wb-card p-8 text-center">
          <p className="text-sm text-[#667085]">No IOCs found in the provided text.</p>
          <p className="text-xs text-[#98a2b3] mt-1">Try pasting logs or text containing IPs, domains, URLs, or file hashes.</p>
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
                      ? 'bg-[#eff8ff] border-[#b2ddff] text-[#175cd3]'
                      : 'bg-white border-[#e4e7ec] text-[#667085] hover:border-[#d0d5dd]'
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
                <tr className="border-b border-[#f2f4f7]">
                  <th className="text-left py-2 px-2 wb-label w-20">Type</th>
                  <th className="text-left py-2 px-2 wb-label">IOC</th>
                  <th className="text-left py-2 px-2 wb-label hidden md:table-cell">Normalised</th>
                  <th className="text-right py-2 px-2 wb-label w-36">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#f9fafb]">
                {filteredResults.map((ioc, i) => (
                  <tr key={i} className="hover:bg-[#f9fafb] transition-colors">
                    <td className="py-2 px-2">
                      <span className="inline-flex items-center h-5 px-2 rounded-md bg-[#eff8ff] border border-[#b2ddff] text-[#175cd3] text-[11px] font-semibold font-mono">
                        {TYPE_LABELS[ioc.type]}
                      </span>
                    </td>
                    <td className="py-2 px-2">
                      <code className="text-[13px] font-mono text-[#344054] break-all">{ioc.raw}</code>
                    </td>
                    <td className="py-2 px-2 hidden md:table-cell">
                      {ioc.normalised !== ioc.raw
                        ? <code className="text-xs font-mono text-[#667085] break-all">{ioc.normalised}</code>
                        : <span className="text-[#d0d5dd]">—</span>}
                    </td>
                    <td className="py-2 px-2 text-right">
                      <div className="flex gap-1.5 justify-end">
                        <CopyButton text={ioc.normalised} label="Copy" />
                        <button onClick={() => onInvestigate(ioc.normalised)}
                          className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-semibold rounded-lg bg-[#1570ef] text-white hover:bg-[#175cd3] transition-colors">
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
