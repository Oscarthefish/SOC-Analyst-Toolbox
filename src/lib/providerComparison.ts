import type { EnrichmentResult, Severity } from '../types/enrichment';

/** Side-by-side comparison of what each provider says, grouped by topic (location, reputation, infrastructure…). */

export interface CompRow {
  provider: string;
  value: string;
  note?: string;        // e.g. "geolocation" vs "registration"
  severity?: Severity;
  url?: string;
  highlight?: boolean;  // flag discrepancy / notable fact
}

export interface CompGroup {
  label: string;
  rows: CompRow[];
}

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4, benign: 5 };

export function buildComparison(results: EnrichmentResult[], iocType: string): CompGroup[] {
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
