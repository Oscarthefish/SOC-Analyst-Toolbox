import type { HistoryEntry } from '../lib/searchHistory';

interface SearchHistoryPanelProps {
  entries: HistoryEntry[];
  onLoad: (entry: HistoryEntry) => void;
  onRemove: (id: string) => void;
  onClear: () => void;
}

const TYPE_LABELS: Record<string, string> = {
  ipv4: 'IPv4', ipv6: 'IPv6', domain: 'Domain', url: 'URL',
  md5: 'MD5', sha1: 'SHA-1', sha256: 'SHA-256', email: 'Email',
  asn: 'ASN', cidr: 'CIDR', cve: 'CVE',
};

const SEV_STYLES: Record<string, { bg: string; text: string; border: string; dot: string }> = {
  critical: { bg: 'bg-[#fef3f2]', text: 'text-[#b42318]', border: 'border-[#fecdca]', dot: 'bg-[#d92d20]' },
  high:     { bg: 'bg-[#fef3f2]', text: 'text-[#b42318]', border: 'border-[#fecdca]', dot: 'bg-[#d92d20]' },
  medium:   { bg: 'bg-[#fffaeb]', text: 'text-[#b54708]', border: 'border-[#fedf89]', dot: 'bg-[#dc6803]' },
  low:      { bg: 'bg-[#eff8ff]', text: 'text-[#175cd3]', border: 'border-[#b2ddff]', dot: 'bg-[#1570ef]' },
  benign:   { bg: 'bg-[#ecfdf3]', text: 'text-[#067647]', border: 'border-[#abefc6]', dot: 'bg-[#079455]' },
  unknown:  { bg: 'bg-[#f2f4f7]', text: 'text-[#344054]', border: 'border-[#e4e7ec]', dot: 'bg-[#98a2b3]' },
};

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60_000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d === 1) return 'yesterday';
  return `${d}d ago`;
}

function ClockIcon() {
  return (
    <svg className="w-10 h-10 text-[#d0d5dd]" fill="none" stroke="currentColor" strokeWidth={1.4} viewBox="0 0 24 24">
      <circle cx="12" cy="12" r="10" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6l4 2" />
    </svg>
  );
}

export function SearchHistoryPanel({ entries, onLoad, onRemove, onClear }: SearchHistoryPanelProps) {
  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[15px] font-semibold text-[#101828]">Search History</h2>
          <p className="text-xs text-[#98a2b3] mt-0.5">
            Last {entries.length === 0 ? '0' : `${entries.length}`} of 10 searches — auto-saved, loaded instantly
          </p>
        </div>
        {entries.length > 0 && (
          <button
            onClick={onClear}
            className="text-xs font-medium text-[#98a2b3] hover:text-[#d92d20] transition-colors px-3 py-1.5 rounded-lg border border-[#e4e7ec] hover:border-[#fecdca] bg-white"
          >
            Clear all
          </button>
        )}
      </div>

      {/* Empty state */}
      {entries.length === 0 && (
        <div className="wb-card p-12 flex flex-col items-center gap-3 text-center">
          <ClockIcon />
          <div>
            <p className="text-sm font-medium text-[#344054]">No searches saved yet</p>
            <p className="text-xs text-[#98a2b3] mt-1 max-w-[300px] leading-relaxed">
              Run an analysis from the Single IOC tab — results are saved here automatically.
            </p>
          </div>
        </div>
      )}

      {/* Entry list */}
      {entries.length > 0 && (
        <div className="space-y-2">
          {entries.map(entry => {
            const sev = entry.result.overall.severity ?? 'unknown';
            const sevStyle = SEV_STYLES[sev] ?? SEV_STYLES['unknown']!;
            const iocType = entry.ioc.type;
            const okCount = entry.result.results.filter(r => r.status === 'ok' || r.status === 'cached').length;
            const totalCount = entry.result.results.length;

            return (
              <div
                key={entry.id}
                className="wb-card overflow-hidden"
              >
                {/* Severity stripe */}
                <div className={`h-1 ${sevStyle.dot}`} />

                <div className="p-4">
                  <div className="flex items-start gap-3">
                    {/* Left: IOC info */}
                    <div className="flex-1 min-w-0 space-y-2">
                      {/* IOC value */}
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="inline-flex items-center h-5 px-2 rounded-full text-[10px] font-semibold bg-[#eff8ff] border border-[#b2ddff] text-[#175cd3]">
                          {TYPE_LABELS[iocType] ?? iocType}
                        </span>
                        <code className="text-[13px] font-mono text-[#101828] font-medium truncate max-w-[320px]">
                          {entry.ioc.normalised}
                        </code>
                      </div>

                      {/* Verdict + meta row */}
                      <div className="flex items-center gap-2 flex-wrap">
                        {/* Severity badge */}
                        <span className={`inline-flex items-center gap-1.5 h-5 px-2 rounded-full text-[10px] font-semibold border ${sevStyle.bg} ${sevStyle.border} ${sevStyle.text}`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${sevStyle.dot}`} />
                          {sev.charAt(0).toUpperCase() + sev.slice(1)}
                        </span>

                        {/* Provider count */}
                        <span className="text-[11px] text-[#98a2b3]">
                          {okCount}/{totalCount} providers
                        </span>

                        {/* Workflow */}
                        {entry.workflowId && (
                          <span className="text-[11px] text-[#667085] bg-[#f2f4f7] px-1.5 py-0.5 rounded font-medium">
                            {entry.workflowId}
                          </span>
                        )}

                        {/* Timestamp */}
                        <span className="text-[11px] text-[#98a2b3] ml-auto">
                          {relativeTime(entry.savedAt)}
                        </span>
                      </div>

                      {/* Narrative preview */}
                      {entry.result.narrative && (
                        <p className="text-[11px] text-[#667085] leading-relaxed line-clamp-2">
                          {entry.result.narrative.replace(/\*+/g, '').replace(/^(VERDICT|KEY FINDINGS|RECOMMENDED ACTIONS|ANALYST NOTES):/gim, '').trim().slice(0, 180)}
                        </p>
                      )}
                    </div>

                    {/* Right: actions */}
                    <div className="flex flex-col gap-1.5 shrink-0">
                      <button
                        onClick={() => onLoad(entry)}
                        className="text-xs font-semibold px-3 py-1.5 rounded-lg bg-[#1570ef] text-white hover:bg-[#175cd3] transition-colors whitespace-nowrap"
                      >
                        Load
                      </button>
                      <button
                        onClick={() => onRemove(entry.id)}
                        className="text-xs font-medium px-3 py-1.5 rounded-lg border border-[#e4e7ec] bg-white text-[#98a2b3] hover:text-[#d92d20] hover:border-[#fecdca] transition-colors"
                      >
                        Remove
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
