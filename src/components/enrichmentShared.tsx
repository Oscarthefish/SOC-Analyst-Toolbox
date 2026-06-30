import { useState, useCallback } from 'react';
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

// ── Provider Comparison Panel ──────────────────────────────────────────────

interface CompRow {
  provider: string;
  value: string;
  note?: string;        // e.g. "geolocation" vs "registration"
  severity?: Severity;
  url?: string;
  highlight?: boolean;  // flag discrepancy / notable fact
}

interface CompGroup {
  label: string;
  rows: CompRow[];
}

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4, benign: 5 };

function buildComparison(results: EnrichmentResult[], iocType: string): CompGroup[] {
  const ok = (id: string) => results.find(r => r.providerId === id && (r.status === 'ok' || r.status === 'cached'));
  const fact = (r: EnrichmentResult | undefined, label: string): string | null =>
    r?.keyFacts?.find(f => f.label === label)?.value ?? null;
  const compact = (...parts: (string | null | false | undefined)[]) =>
    parts.filter(Boolean).join(' · ') || null;

  const groups: CompGroup[] = [];

  // ── IP address ──────────────────────────────────────────────────────────
  if (iocType === 'ipv4' || iocType === 'ipv6') {
    const whois    = ok('whois');
    const ipapi    = ok('ipapi');
    const ipinfo   = ok('ipinfo');
    const abuse    = ok('abuseipdb');
    const gn       = ok('greynoise');
    const vt       = ok('virustotal');
    const shodan   = ok('shodan');
    const censys   = ok('censys');
    const tor      = ok('torproject');

    // ── Location & Network ──
    const locRows: CompRow[] = [];

    if (whois) {
      const country = fact(whois, 'Country (registration)');
      const network = fact(whois, 'Network') ?? fact(whois, 'Registrant org');
      const desc    = fact(whois, 'Description');
      const v = compact(country && `${country} (reg)`, network, desc);
      if (v) locRows.push({ provider: 'WHOIS', value: v, note: 'registration', url: whois.sourceUrl ?? undefined });
    }

    if (ipapi) {
      const loc    = fact(ipapi, 'Location');
      const isp    = fact(ipapi, 'ISP / Org');
      const asn    = fact(ipapi, 'ASN');
      const isDC   = fact(ipapi, 'Datacenter / Hosting') === 'Yes';
      const isVPN  = fact(ipapi, 'VPN / Proxy') === 'Yes';
      const v = compact(loc, isp, asn, isDC && 'Datacenter', isVPN && 'VPN/Proxy');
      if (v) locRows.push({ provider: 'ip-api', value: v, note: 'geolocation', url: ipapi.sourceUrl ?? undefined });
    }

    if (ipinfo && !ipapi) {
      const loc  = fact(ipinfo, 'Location') ?? fact(ipinfo, 'Country');
      const org  = fact(ipinfo, 'Org') ?? fact(ipinfo, 'ISP / Org');
      const asn  = fact(ipinfo, 'ASN');
      const v = compact(loc, org, asn);
      if (v) locRows.push({ provider: 'ipinfo', value: v, note: 'geolocation', url: ipinfo.sourceUrl ?? undefined });
    }

    if (abuse) {
      const country = fact(abuse, 'Country');
      const isp     = fact(abuse, 'ISP');
      const v = compact(country, isp && `ISP: ${isp}`);
      if (v) locRows.push({ provider: 'AbuseIPDB', value: v, url: abuse.sourceUrl ?? undefined });
    }

    if (shodan) {
      const country = fact(shodan, 'Country');
      const org     = fact(shodan, 'Org') ?? fact(shodan, 'ISP');
      const asn     = fact(shodan, 'ASN');
      const v = compact(country, org, asn);
      if (v) locRows.push({ provider: 'Shodan', value: v, url: shodan.sourceUrl ?? undefined });
    }

    if (censys) {
      const country = fact(censys, 'Country');
      const org     = fact(censys, 'Org');
      const asn     = fact(censys, 'ASN');
      const v = compact(country, org, asn);
      if (v) locRows.push({ provider: 'Censys', value: v, url: censys.sourceUrl ?? undefined });
    }

    // Highlight country discrepancies (registration vs geolocation)
    const regCountry = fact(whois, 'Country (registration)')?.toUpperCase();
    const geoCountry = (fact(ipapi, 'Location') ?? fact(ipinfo, 'Country') ?? '').split(',')[0]?.trim().toUpperCase();
    if (regCountry && geoCountry && regCountry !== geoCountry && geoCountry.length > 0) {
      locRows.forEach(r => { if (r.provider === 'WHOIS' || r.note === 'geolocation') r.highlight = true; });
    }

    if (locRows.length) groups.push({ label: 'Location & Network', rows: locRows });

    // ── Reputation ──
    const repRows: CompRow[] = [];

    if (abuse) {
      const score   = fact(abuse, 'Abuse score');
      const reports = fact(abuse, 'Report count');
      const last    = fact(abuse, 'Last report');
      const v = compact(score && `${score} confidence`, reports && `${reports} reports`, last && `last: ${last}`);
      if (v) repRows.push({ provider: 'AbuseIPDB', value: v, severity: abuse.severity, url: abuse.sourceUrl ?? undefined });
    }

    if (gn) {
      const cls    = fact(gn, 'Classification');
      const name   = fact(gn, 'Name');
      const noise  = fact(gn, 'Internet noise') === 'yes' ? 'internet noise' : null;
      const riot   = fact(gn, 'RIOT') === 'yes — known good service' ? 'RIOT/known service' : null;
      const last   = fact(gn, 'Last seen');
      const v = compact(cls, name, noise, riot, last && `last seen ${last}`);
      if (v) repRows.push({ provider: 'GreyNoise', value: v, severity: gn.severity, url: gn.sourceUrl ?? undefined });
    }

    if (vt) {
      const det = fact(vt, 'Detection ratio');
      const cat = fact(vt, 'Threat category');
      const v = compact(det && `${det} detections`, cat);
      if (v) repRows.push({ provider: 'VirusTotal', value: v, severity: vt.severity, url: vt.sourceUrl ?? undefined });
    }

    if (tor && tor.severity !== 'benign' && tor.severity !== 'unknown') {
      repRows.push({ provider: 'Tor Project', value: 'Confirmed Tor exit node', severity: tor.severity, url: tor.sourceUrl ?? undefined });
    }

    repRows.sort((a, b) => (SEV_RANK[a.severity ?? 'unknown'] ?? 4) - (SEV_RANK[b.severity ?? 'unknown'] ?? 4));
    if (repRows.length) groups.push({ label: 'Reputation', rows: repRows });

    // ── Exposure ──
    const expRows: CompRow[] = [];

    if (shodan) {
      const ports   = fact(shodan, 'Open ports');
      const scanned = fact(shodan, 'Last scanned');
      const vulns   = fact(shodan, 'CVEs (Shodan)');
      const hosts   = fact(shodan, 'Hostnames');
      const v = compact(ports && `${ports} open`, vulns && `CVEs: ${vulns}`, scanned && `scanned ${scanned}`, hosts && `Hostnames: ${hosts}`);
      if (v) expRows.push({ provider: 'Shodan', value: v, url: shodan.sourceUrl ?? undefined, highlight: !!vulns });
    }

    if (censys) {
      const ports = fact(censys, 'Open ports');
      const v = compact(ports && `${ports} open`);
      if (v) expRows.push({ provider: 'Censys', value: v, url: censys.sourceUrl ?? undefined });
    }

    if (gn) {
      const noise = fact(gn, 'Internet noise');
      const last  = fact(gn, 'Last seen');
      if (noise === 'yes') expRows.push({ provider: 'GreyNoise', value: compact('Internet background noise', last && `last seen ${last}`) ?? 'Internet noise', url: gn.sourceUrl ?? undefined });
    }

    if (expRows.length) groups.push({ label: 'Exposure', rows: expRows });

  // ── Domain / URL ────────────────────────────────────────────────────────
  } else if (iocType === 'domain' || iocType === 'url') {
    const whois   = ok('whois');
    const vt      = ok('virustotal');
    const sb      = ok('safebrowsing');
    const urlscan = ok('urlscan');
    const crtsh   = ok('crtsh');
    const wayback = ok('wayback');
    const shodan  = ok('shodan');
    const censys  = ok('censys');
    const hunter  = ok('hunter');

    // ── Registration & History ──
    const regRows: CompRow[] = [];

    if (whois) {
      const age       = fact(whois, 'Domain age');
      const registrar = fact(whois, 'Registrar');
      const registrant= fact(whois, 'Registrant org');
      const expires   = fact(whois, 'Expires');
      const v = compact(age && `Age: ${age}`, registrar && `Registrar: ${registrar}`, registrant && `Registrant: ${registrant}`, expires && `Expires: ${expires}`);
      if (v) regRows.push({ provider: 'WHOIS', value: v, severity: whois.severity, url: whois.sourceUrl ?? undefined });
    }

    if (crtsh) {
      const certs = fact(crtsh, 'Certificates');
      const SANs  = fact(crtsh, 'Unique SANs');
      const issuer= fact(crtsh, 'Top issuer');
      const latest= fact(crtsh, 'Latest cert');
      const v = compact(certs && `${certs} certs`, SANs && `${SANs} SANs`, issuer && `Issuer: ${issuer}`, latest && `Latest: ${latest}`);
      if (v) regRows.push({ provider: 'crt.sh', value: v, url: crtsh.sourceUrl ?? undefined });
    }

    if (wayback) {
      const first = fact(wayback, 'First archived');
      const last  = fact(wayback, 'Latest snapshot');
      const v = compact(first && `First archived: ${first}`, last && `Latest: ${last}`);
      if (v) regRows.push({ provider: 'Wayback', value: v, url: wayback.sourceUrl ?? undefined });
    }

    if (hunter) {
      const company = fact(hunter, 'Company');
      const emails  = fact(hunter, 'Emails found');
      const v = compact(company && `Company: ${company}`, emails && `${emails} emails found`);
      if (v) regRows.push({ provider: 'Hunter.io', value: v, url: hunter.sourceUrl ?? undefined });
    }

    if (regRows.length) groups.push({ label: 'Registration & History', rows: regRows });

    // ── Reputation ──
    const repRows: CompRow[] = [];

    if (vt) {
      const det = fact(vt, 'Detection ratio');
      const cat = fact(vt, 'Threat category');
      const v = compact(det && `${det} detections`, cat);
      if (v) repRows.push({ provider: 'VirusTotal', value: v, severity: vt.severity, url: vt.sourceUrl ?? undefined });
    }

    if (sb) {
      const threats = fact(sb, 'Threat types') ?? fact(sb, 'Safe Browsing');
      if (threats) repRows.push({ provider: 'Safe Browsing', value: threats, severity: sb.severity, url: sb.sourceUrl ?? undefined });
    }

    if (urlscan) {
      const verdict = fact(urlscan, 'Latest verdict');
      const scans   = fact(urlscan, 'Total scans');
      const title   = fact(urlscan, 'Page title');
      const v = compact(verdict, scans && `${scans} scans`, title && `"${title}"`);
      if (v) repRows.push({ provider: 'URLscan', value: v, severity: urlscan.severity, url: urlscan.sourceUrl ?? undefined });
    }

    repRows.sort((a, b) => (SEV_RANK[a.severity ?? 'unknown'] ?? 4) - (SEV_RANK[b.severity ?? 'unknown'] ?? 4));
    if (repRows.length) groups.push({ label: 'Reputation', rows: repRows });

    // ── Infrastructure ──
    const infraRows: CompRow[] = [];

    if (shodan) {
      const ports = fact(shodan, 'Open ports');
      const org   = fact(shodan, 'Org') ?? fact(shodan, 'ISP');
      const vulns = fact(shodan, 'CVEs (Shodan)');
      const v = compact(ports && `${ports} open`, org, vulns && `CVEs: ${vulns}`);
      if (v) infraRows.push({ provider: 'Shodan', value: v, url: shodan.sourceUrl ?? undefined, highlight: !!vulns });
    }

    if (censys) {
      const ports = fact(censys, 'Open ports');
      const org   = fact(censys, 'Org');
      const v = compact(ports && `${ports} open`, org);
      if (v) infraRows.push({ provider: 'Censys', value: v, url: censys.sourceUrl ?? undefined });
    }

    if (infraRows.length) groups.push({ label: 'Infrastructure', rows: infraRows });
  }

  return groups;
}

export function ProviderComparisonPanel({ results, iocType }: { results: EnrichmentResult[]; iocType: string }) {
  const [copied, setCopied] = useState(false);
  const groups = buildComparison(results, iocType);

  const handleCopy = useCallback(() => {
    const lines: string[] = [];
    groups.forEach(g => {
      lines.push(g.label.toUpperCase());
      g.rows.forEach(r => {
        const sev = r.severity && r.severity !== 'unknown' ? ` [${r.severity.toUpperCase()}]` : '';
        lines.push(`  ${r.provider}: ${r.value}${sev}`);
      });
      lines.push('');
    });
    void navigator.clipboard.writeText(lines.join('\n').trim()).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [groups]);

  if (groups.length === 0) return null;

  return (
    <div className="rounded-[10px] border border-[#e4e7ec] overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 bg-[#fafbfc] border-b border-[#f2f4f7]">
        <p className="text-[11px] font-bold uppercase tracking-wider text-[#667085]">Provider Intel Summary</p>
        <button
          onClick={handleCopy}
          title="Copy summary"
          className="flex items-center gap-1 text-[11px] text-[#667085] hover:text-[#344054] font-medium transition-colors"
        >
          {copied ? (
            <>
              <svg className="w-3 h-3 text-[#079455]" fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
              </svg>
              <span className="text-[#079455]">Copied</span>
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
      </div>

      {/* Groups */}
      <div className="divide-y divide-[#f2f4f7]">
        {groups.map(g => (
          <div key={g.label} className="px-3 py-2.5">
            <p className="text-[9px] font-bold uppercase tracking-widest text-[#98a2b3] mb-2">{g.label}</p>
            <div className="space-y-1.5">
              {g.rows.map((row, i) => (
                <div key={i} className={`flex items-start gap-2 text-[11px] rounded px-1.5 py-1 -mx-1.5 ${row.highlight ? 'bg-[#fffaeb]' : ''}`}>
                  {/* Provider name */}
                  <span className="w-[80px] shrink-0 font-semibold text-[#344054] truncate">{row.provider}</span>

                  {/* Value */}
                  <span className="flex-1 text-[#475467] break-words leading-snug min-w-0">
                    {row.value}
                    {row.note && <span className="ml-1 text-[#98a2b3]">({row.note})</span>}
                    {row.highlight && (
                      <svg className="inline w-3 h-3 text-[#dc6803] ml-1 shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01M12 3l9 16H3L12 3z" />
                      </svg>
                    )}
                  </span>

                  {/* Severity chip */}
                  {row.severity && row.severity !== 'unknown' && (
                    <span className={`shrink-0 text-[9px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded border ${SEV_CHIP[row.severity] ?? ''}`}>
                      {row.severity}
                    </span>
                  )}

                  {/* Source link */}
                  {row.url && (
                    <a href={row.url} target="_blank" rel="noopener noreferrer" title="View source"
                      className="shrink-0 text-[#98a2b3] hover:text-[#1570ef] transition-colors">
                      <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
                        <polyline points="15 3 21 3 21 9" /><line x1="10" y1="14" x2="21" y2="3" />
                      </svg>
                    </a>
                  )}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
