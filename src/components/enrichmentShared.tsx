import { useState } from 'react';
import type { EnrichmentResult, ContradictionFlag, Severity } from '../types/enrichment';

// ── Types ──────────────────────────────────────────────────────────────────

export interface SummaryFact {
  label: string;
  value: string;
  source: string;
  severity?: Severity;
}

// ── Helpers ────────────────────────────────────────────────────────────────

export function extractSummaryFacts(results: EnrichmentResult[]): SummaryFact[] {
  const facts: SummaryFact[] = [];
  const ok = results.filter(r => r.status === 'ok' || r.status === 'cached');

  const find = (id: string) => ok.find(r => r.providerId === id);
  const findFact = (r: EnrichmentResult | undefined, label: string) =>
    r?.keyFacts?.find(f => f.label === label)?.value;

  const vt = find('virustotal');
  const vtRatio = findFact(vt, 'Detection ratio');
  if (vtRatio) facts.push({ label: 'VT Detection', value: vtRatio, source: 'VirusTotal', severity: vt?.severity });

  const abuse = find('abuseipdb');
  const abScore = findFact(abuse, 'Abuse score');
  if (abScore) facts.push({ label: 'Abuse Score', value: abScore, source: 'AbuseIPDB', severity: abuse?.severity });

  const gn = find('greynoise');
  const gnCls = findFact(gn, 'Classification');
  if (gnCls && gnCls !== 'unknown') facts.push({ label: 'GreyNoise', value: gnCls, source: 'GreyNoise', severity: gn?.severity });

  const kev = find('cisakev');
  if (kev && kev.severity === 'critical') {
    facts.push({ label: 'CISA KEV', value: 'Actively exploited', source: 'CISA', severity: 'critical' });
  }

  const rwl = find('ransomwarelive');
  if (rwl && rwl.severity === 'critical') {
    const group = findFact(rwl, 'Ransomware group(s)');
    facts.push({ label: 'Ransomware', value: group ? `Victim — ${group}` : 'Listed as victim', source: 'Ransomware.live', severity: 'critical' });
  }

  const tf = find('threatfox');
  const tfFamilies = findFact(tf, 'Malware families');
  if (tfFamilies) facts.push({ label: 'Malware', value: tfFamilies, source: 'ThreatFox', severity: tf?.severity });

  const mb = find('malwarebazaar');
  const mbFamily = findFact(mb, 'Malware family');
  if (mbFamily) facts.push({ label: 'Family', value: mbFamily, source: 'MalwareBazaar', severity: mb?.severity });

  const withDate = ok.filter(r => r.lastSeenDate).sort((a, b) =>
    new Date(b.lastSeenDate!).getTime() - new Date(a.lastSeenDate!).getTime());
  if (withDate.length > 0) {
    const r = withDate[0]!;
    facts.push({ label: 'Last Seen', value: r.lastSeenDate!.split('T')[0]!, source: r.providerName });
  }

  const ipapi = find('ipapi');
  const usageType = findFact(ipapi, 'Usage type');
  if (usageType) facts.push({ label: 'Usage', value: usageType, source: 'ip-api' });

  const whois = find('whois');
  if (whois && typeof whois.data.domainAge === 'number') {
    const age = whois.data.domainAge as number;
    facts.push({ label: 'Domain Age', value: age <= 30 ? `${age}d — newly registered` : `${age}d`, source: 'WHOIS', severity: age <= 14 ? 'medium' : undefined });
  }

  const hunter = find('hunter');
  const hunterCompany = findFact(hunter, 'Company');
  if (hunterCompany) facts.push({ label: 'Company', value: hunterCompany, source: 'Hunter.io' });

  const wayback = find('wayback');
  const waybackFirst = findFact(wayback, 'First archived');
  if (waybackFirst) facts.push({ label: 'First archived', value: waybackFirst, source: 'Wayback Machine' });

  return facts.slice(0, 8);
}

export const SEV_CHIP: Record<string, string> = {
  critical: 'bg-[#fef3f2] border-[#fecdca] text-[#b42318]',
  high:     'bg-[#fef3f2] border-[#fecdca] text-[#b42318]',
  medium:   'bg-[#fffaeb] border-[#fedf89] text-[#b54708]',
  low:      'bg-[#eff8ff] border-[#b2ddff] text-[#175cd3]',
  benign:   'bg-[#ecfdf3] border-[#abefc6] text-[#067647]',
};

// ── KeyFactsSummaryStrip ───────────────────────────────────────────────────

export function KeyFactsSummaryStrip({ results }: { results: EnrichmentResult[] }) {
  const facts = extractSummaryFacts(results);
  if (facts.length === 0) return null;
  return (
    <div className="rounded-lg border border-[#e4e7ec] bg-[#fafbfc] px-3 py-2.5">
      <p className="text-[10px] font-semibold text-[#98a2b3] uppercase tracking-wider mb-2">Key Facts</p>
      <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
        {facts.map((f, i) => (
          <div key={i} className="flex items-start gap-1.5 min-w-0">
            <span className="text-[11px] text-[#667085] shrink-0 w-20 truncate">{f.label}</span>
            <span className={`text-[11px] font-semibold truncate px-1.5 py-0 rounded border ${
              f.severity && SEV_CHIP[f.severity] ? SEV_CHIP[f.severity] : 'text-[#101828] border-transparent bg-transparent'
            }`}>
              {f.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── PivotSection ───────────────────────────────────────────────────────────

export function PivotSection({ items, label, color, onPivot }: {
  items: string[];
  label: string;
  color: 'blue' | 'purple';
  onPivot: (value: string) => void;
}) {
  const [showAll, setShowAll] = useState(false);
  const unique = Array.from(new Set(items));
  if (unique.length === 0) return null;
  const LIMIT = 6;
  const visible = showAll ? unique : unique.slice(0, LIMIT);
  const hidden = unique.length - LIMIT;

  const { bg, border, text, hover } = color === 'blue'
    ? { bg: 'bg-[#eff8ff]', border: 'border-[#b2ddff]', text: 'text-[#175cd3]', hover: 'hover:bg-[#1570ef] hover:text-white hover:border-[#1570ef]' }
    : { bg: 'bg-[#f4f3ff]', border: 'border-[#d9d6fe]', text: 'text-[#5925dc]', hover: 'hover:bg-[#7a5af8] hover:text-white hover:border-[#7a5af8]' };

  return (
    <div className={`rounded-lg border ${border} ${bg} px-3.5 py-2.5`}>
      <div className="flex items-center gap-2 mb-2">
        <svg className={`w-3.5 h-3.5 ${text} shrink-0`} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
          <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
        </svg>
        <p className={`text-[10px] font-semibold ${text} uppercase tracking-wider`}>{label}</p>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {visible.map(item => (
          <button
            key={item}
            onClick={() => onPivot(item)}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-white border ${border} ${text} text-xs font-mono font-medium ${hover} transition-colors`}
            title={`Investigate ${item}`}
          >
            {item}
            <svg className="w-3 h-3 opacity-60" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 12h14M12 5l7 7-7 7" />
            </svg>
          </button>
        ))}
        {!showAll && hidden > 0 && (
          <button
            onClick={() => setShowAll(true)}
            className={`px-2.5 py-1 rounded-md bg-white border ${border} ${text} text-xs font-medium opacity-60 hover:opacity-100 transition-opacity`}
          >
            +{hidden} more
          </button>
        )}
      </div>
    </div>
  );
}

// ── ContradictionBanner ────────────────────────────────────────────────────

export function ContradictionBanner({ contradictions }: { contradictions: ContradictionFlag[] }) {
  const [expanded, setExpanded] = useState(false);
  if (contradictions.length === 0) return null;
  return (
    <div className="rounded-lg border border-[#fedf89] bg-[#fffaeb] overflow-hidden">
      <button
        onClick={() => setExpanded(v => !v)}
        className="w-full flex items-center gap-2.5 px-3.5 py-2.5 text-left hover:bg-[#fef9e7] transition-colors"
      >
        <svg className="w-4 h-4 text-[#b54708] shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
        </svg>
        <span className="text-xs font-semibold text-[#b54708] flex-1">
          {contradictions.length} source conflict{contradictions.length > 1 ? 's' : ''} detected — review before acting
        </span>
        <svg className={`w-3.5 h-3.5 text-[#b54708] transition-transform ${expanded ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {expanded && (
        <div className="px-3.5 pb-3 space-y-3 border-t border-[#fedf89]">
          {contradictions.map((c, i) => (
            <div key={i} className="pt-3">
              <p className="text-xs font-semibold text-[#b54708] font-mono mb-1">{c.type}</p>
              <p className="text-xs text-[#92400e] mb-1">{c.message}</p>
              <p className="text-xs text-[#78350f] opacity-80">→ {c.recommendation}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
