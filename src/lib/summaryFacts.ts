import type { EnrichmentResult, Severity } from '../types/enrichment';

/** The headline facts across providers (e.g. abuse score, ASN, domain age), for the result summary. */

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
