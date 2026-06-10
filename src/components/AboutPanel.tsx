const INTEGRATIONS = [
  // No key required
  { name: 'DNS Resolution',      id: 'dns',            tier: 'free',  keyRequired: false, supports: ['Domain'],                            desc: 'Node.js built-in resolver. Returns IPv4/IPv6 records and pivot links to each resolved IP.' },
  { name: 'RIPE Stat',           id: 'bgpview',        tier: 'free',  keyRequired: false, supports: ['IPv4', 'IPv6', 'ASN', 'CIDR'],       desc: 'BGP routing and prefix data from RIPE NCC. ASN holder, country, and announcement status.' },
  { name: 'CISA KEV',            id: 'cisakev',        tier: 'free',  keyRequired: false, supports: ['CVE'],                               desc: 'CISA Known Exploited Vulnerabilities catalogue. Flags CVEs actively exploited in the wild.' },
  { name: 'Ransomware.live',     id: 'ransomwarelive', tier: 'free',  keyRequired: false, supports: ['Domain'],                            desc: 'Public ransomware victim listing. Checks if a domain appears in known ransomware group postings.' },
  { name: 'crt.sh',              id: 'crtsh',          tier: 'free',  keyRequired: false, supports: ['Domain'],                            desc: 'Certificate transparency logs. Extracts SANs from recent TLS certificates to pivot to related subdomains.' },
  { name: 'Wayback Machine',     id: 'wayback',        tier: 'free',  keyRequired: false, supports: ['Domain'],                            desc: 'Internet Archive CDX API. Returns first and most recent snapshot dates — useful for detecting re-registered domains.' },
  { name: 'Tor Project (Onionoo)',id: 'torproject',    tier: 'free',  keyRequired: false, supports: ['IPv4', 'IPv6'],                      desc: 'Onionoo relay database. Identifies whether an IP is a Tor exit node, guard, or relay.' },
  { name: 'ip-api',              id: 'ipapi',          tier: 'free',  keyRequired: false, supports: ['IPv4', 'IPv6'],                      desc: 'Free IP geolocation. Country, city, ISP, usage type (datacenter, residential, etc.).' },
  // Free key required
  { name: 'GreyNoise',           id: 'greynoise',      tier: 'free',  keyRequired: true,  supports: ['IPv4', 'IPv6'],                      desc: 'Internet noise classification. Labels IPs as scanners, crawlers, or known malicious actors vs. targeted traffic.' },
  { name: 'AbuseIPDB',           id: 'abuseipdb',      tier: 'free',  keyRequired: true,  supports: ['IPv4', 'IPv6'],                      desc: 'Community abuse reporting. Abuse confidence score and report history for IP addresses.' },
  { name: 'VirusTotal',          id: 'virustotal',     tier: 'free',  keyRequired: true,  supports: ['IPv4', 'IPv6', 'Domain', 'MD5', 'SHA1', 'SHA256'], desc: 'Multi-engine reputation lookup. Detection ratio across 70+ AV engines and threat intelligence feeds.' },
  { name: 'AlienVault OTX',      id: 'otx',            tier: 'free',  keyRequired: true,  supports: ['IPv4', 'IPv6', 'Domain', 'URL', 'MD5', 'SHA1', 'SHA256'], desc: 'Crowd-sourced threat intelligence pulses. IOC associations with malware families and threat actors.' },
  { name: 'ThreatFox',           id: 'threatfox',      tier: 'free',  keyRequired: true,  supports: ['IPv4', 'IPv6', 'Domain', 'URL', 'MD5', 'SHA1', 'SHA256'], desc: 'abuse.ch IOC database. Malware C2s, payloads, and threat actor infrastructure.' },
  { name: 'URLhaus',             id: 'urlhaus',        tier: 'free',  keyRequired: true,  supports: ['URL', 'Domain', 'IPv4'],             desc: 'abuse.ch malicious URL database. Checks active and historical malware delivery URLs.' },
  { name: 'MalwareBazaar',       id: 'malwarebazaar',  tier: 'free',  keyRequired: true,  supports: ['MD5', 'SHA1', 'SHA256'],             desc: 'abuse.ch malware hash database. File type, malware family, tags, and vendor detections. Uses the same key as URLhaus.' },
  { name: 'urlscan.io',          id: 'urlscan',        tier: 'free',  keyRequired: true,  supports: ['Domain', 'URL', 'IPv4'],             desc: 'Historical URL scan search. Screenshots, DOM content, and outbound links from automated scans.' },
  { name: 'Pulsedive',           id: 'pulsedive',      tier: 'free',  keyRequired: true,  supports: ['IPv4', 'IPv6', 'Domain', 'URL'],     desc: 'Risk-scored TI platform. Linked IOC relationships, threat categories, and active feed memberships.' },
  { name: 'Hybrid Analysis',     id: 'hybridanalysis', tier: 'free',  keyRequired: true,  supports: ['MD5', 'SHA1', 'SHA256'],             desc: 'Sandbox report lookup. Verdict, threat score, AV detections, and malware family from dynamic analysis.' },
  { name: 'IPinfo',              id: 'ipinfo',         tier: 'free',  keyRequired: true,  supports: ['IPv4', 'IPv6'],                      desc: 'IP geolocation and ASN data. Privacy plan adds VPN, proxy, and Tor detection flags.' },
  { name: 'Hunter.io',           id: 'hunter',         tier: 'free',  keyRequired: true,  supports: ['Domain'],                            desc: 'Business domain intelligence. Company profile, industry, employee count, email pattern, and LinkedIn.' },
  // Paid / limited
  { name: 'Shodan',              id: 'shodan',         tier: 'paid',  keyRequired: true,  supports: ['IPv4', 'IPv6'],                      desc: 'Internet-wide scanner. Open ports, service banners, CVE exposure, hostnames, and organisation data.' },
  { name: 'Censys',              id: 'censys',         tier: 'paid',  keyRequired: true,  supports: ['IPv4', 'IPv6'],                      desc: 'Internet exposure data. Open ports, TLS services, and autonomous system information.' },
  { name: 'HaveIBeenPwned',      id: 'hibp',           tier: 'paid',  keyRequired: true,  supports: ['Email'],                             desc: 'Email breach lookup. Breach count, sensitive flag, exposed data classes, and source breach names.' },
  { name: 'WhoisXML API',        id: 'whois',          tier: 'paid',  keyRequired: false, supports: ['Domain', 'IPv4', 'IPv6'],            desc: 'WHOIS registration data. Domain age, registrar, registrant org, expiry, and nameservers. Falls back to free RDAP if no key.' },
  { name: 'Google Safe Browsing',id: 'safebrowsing',   tier: 'paid',  keyRequired: true,  supports: ['URL', 'Domain'],                     desc: 'Google threat blocklists. Malware, phishing, unwanted software, and harmful application classifications.' },
];

const WORKFLOWS = [
  { id: 'ip-triage',           name: 'IP Triage',                  types: ['IPv4', 'IPv6'],          desc: 'Full enrichment sweep for IP addresses — reputation, geolocation, ASN, Tor, open ports.' },
  { id: 'domain-triage',       name: 'Domain Triage',              types: ['Domain'],                desc: 'DNS resolution, certificate pivots, WHOIS age, threat intelligence, and web archive checks.' },
  { id: 'url-phishing',        name: 'URL / Phishing',             types: ['URL', 'Domain'],         desc: 'URL reputation across Safe Browsing, URLhaus, VirusTotal, and urlscan.io. Targets phish kits.' },
  { id: 'spam-source',         name: 'Spam Source',                types: ['IPv4', 'Email'],         desc: 'Email sender investigation — abuse reports, ASN data, and deliverability checks.' },
  { id: 'malware-hash',        name: 'Malware / Hash',             types: ['MD5', 'SHA1', 'SHA256'], desc: 'Hash lookup across VirusTotal, MalwareBazaar, ThreatFox, OTX, and Hybrid Analysis sandbox.' },
  { id: 'suspicious-connection', name: 'Suspicious Connection',   types: ['IPv4', 'IPv6'],          desc: 'C2 and beaconing investigation — GreyNoise noise classification, Shodan ports, threat feeds.' },
  { id: 'waf-web-attack',      name: 'WAF / Web Attack',           types: ['IPv4'],                  desc: 'Source IP enrichment for web attack traffic — scanner classification and abuse history.' },
  { id: 'dark-web-exposure',   name: 'Dark Web / Credential',      types: ['Domain', 'Email'],       desc: 'Checks for breach exposure and dark web mentions of a domain or email address.' },
  { id: 'takedown-reporting',  name: 'Takedown Reporting',         types: ['Domain', 'URL'],         desc: 'Identifies registrar, hosting, and abuse contact details needed for takedown submissions.' },
  { id: 'ransomware-context',  name: 'Ransomware Context',         types: ['Domain', 'IPv4'],        desc: 'Checks ransomware.live victim listings and cross-references with threat intelligence feeds.' },
  { id: 'external-exposure',   name: 'External Exposure',          types: ['IPv4', 'IPv6'],          desc: 'Shodan and Censys port/service scan to assess externally visible attack surface.' },
  { id: 'cve-context',         name: 'CVE Context',                types: ['CVE'],                   desc: 'CISA KEV lookup — flags if the CVE is under active exploitation in the wild.' },
  { id: 'email-header-review', name: 'Email Header Review',        types: ['Email header'],          desc: 'Parses raw email headers to extract IPs, domains, and sender authentication results.' },
  { id: 'business-domain-osint', name: 'Business Domain Profile',  types: ['Domain'],               desc: 'Corporate intelligence sweep — Hunter.io company data, Wayback history, DNS, certificates, and WHOIS.' },
];

const IOC_TYPES = [
  { type: 'IPv4', example: '8.8.8.8', desc: 'IPv4 address' },
  { type: 'IPv6', example: '2001:4860::1', desc: 'IPv6 address' },
  { type: 'Domain', example: 'evil.example.com', desc: 'Hostname or domain name' },
  { type: 'URL', example: 'https://phish.example/login', desc: 'Full URL' },
  { type: 'MD5', example: 'd41d8cd9…', desc: '32-char hex hash' },
  { type: 'SHA1', example: 'da39a3ee…', desc: '40-char hex hash' },
  { type: 'SHA256', example: 'e3b0c442…', desc: '64-char hex hash' },
  { type: 'Email', example: 'user@domain.com', desc: 'Email address' },
  { type: 'ASN', example: 'AS15169', desc: 'Autonomous system number' },
  { type: 'CIDR', example: '192.0.2.0/24', desc: 'IP subnet in CIDR notation' },
  { type: 'CVE', example: 'CVE-2024-1234', desc: 'Common Vulnerability identifier' },
];

const FEATURES = [
  {
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
        <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
      </svg>
    ),
    title: 'Single IOC Investigation',
    desc: 'Paste any IOC and the tool auto-detects the type. Choose a workflow and run enrichment across multiple providers simultaneously. Results include severity ratings, key facts, pivot links, and AI-generated narrative.',
  },
  {
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h7" />
      </svg>
    ),
    title: 'Bulk IOC Extraction',
    desc: 'Paste raw text — emails, logs, reports, threat intel feeds — and the tool extracts all recognisable IOCs. Deduplicates, classifies by type, and lets you launch single-IOC investigation on any match.',
  },
  {
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
      </svg>
    ),
    title: 'Batch Triage',
    desc: 'Submit up to 50 IOCs at once. The toolbox runs 5 concurrent enrichment jobs, updates a live results table, and produces a severity breakdown bar. One click pivots any result into a full investigation.',
  },
  {
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 2a10 10 0 100 20A10 10 0 0012 2z" />
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3" />
      </svg>
    ),
    title: 'Auto AI Analysis',
    desc: 'Powered by a local Ollama model (no data leaves your machine). After enrichment completes, the AI synthesises all provider results into a plain-English threat assessment with citation enforcement.',
  },
  {
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101" />
        <path strokeLinecap="round" strokeLinejoin="round" d="M14.828 14.828a4 4 0 015.656 0l4-4a4 4 0 01-5.656-5.656l-1.102 1.101" />
      </svg>
    ),
    title: 'Passive DNS & Certificate Pivots',
    desc: 'DNS resolution surfaces resolved IPs as clickable pivot chips. crt.sh certificate transparency logs extract related SANs and subdomains — one click pushes either into the IOC input for immediate investigation.',
  },
  {
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
      </svg>
    ),
    title: 'Contradiction Detection',
    desc: 'Automatically flags when provider results conflict: benign vs. malicious, low VT detections without corroboration, newly registered domains, or WHOIS age mismatches against Wayback archive history.',
  },
  {
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
        <rect x="3" y="3" width="18" height="18" rx="2" />
        <path d="M8 7h.01M12 7h.01M16 7h.01M8 11h.01M12 11h.01M16 11h.01M8 15h.01M12 15h.01" />
        <path d="M9 21v-4h6v4" />
      </svg>
    ),
    title: 'Business OSINT',
    desc: 'The Business Domain Profile workflow aggregates corporate intelligence: Hunter.io company data, Wayback archive history, WHOIS registration, DNS, and certificate transparency logs in a single run.',
  },
  {
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M8 9l3 3-3 3M13 15h3M3 6l3 3-3 3" />
      </svg>
    ),
    title: 'Defang / Refang',
    desc: 'Converts IOCs between defanged (safe to share in reports and Slack) and refanged (ready to investigate) formats. Handles IPv4, IPv6, domains, and URLs in both directions.',
  },
  {
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
      </svg>
    ),
    title: 'Live Threat Feed',
    desc: 'Polls URLhaus and ThreatFox feeds for recent IOC activity. Displays the last 100 entries per feed, lets you filter by type, and pivot any entry directly into a full investigation.',
  },
];

const ARCH_STEPS = [
  { num: '1', title: 'IOC Input', desc: 'Type or paste an IOC. The frontend detects the type using regex patterns and displays relevant workflow tiles.' },
  { num: '2', title: 'Workflow Selection', desc: 'Select a workflow to scope which providers run. Each workflow is tuned for a specific investigation type.' },
  { num: '3', title: 'Backend Enrichment', desc: 'The React frontend calls the local Node.js/Express backend over http://localhost:3001. The backend fans out to all configured providers concurrently.' },
  { num: '4', title: 'Caching', desc: 'Results are cached in-memory by provider TTL (10 min for DNS up to 24 hrs for WHOIS). Repeat lookups are served instantly without burning API quota.' },
  { num: '5', title: 'Scoring & Contradictions', desc: 'The backend computes an overall severity from active (non-passive) sources and runs contradiction detection across the result set.' },
  { num: '6', title: 'AI Narrative', desc: 'Optionally, the backend calls a local Ollama model to synthesise all results into a plain-English assessment. Nothing leaves your machine.' },
  { num: '7', title: 'Results Rendered', desc: 'The frontend displays provider cards, a key facts summary strip, pivot chips, contradiction banners, and the AI narrative.' },
];

function Badge({ label, color }: { label: string; color: 'green' | 'blue' | 'orange' | 'gray' }) {
  const cls = {
    green: 'bg-[#ecfdf3] border-[#abefc6] text-[#067647]',
    blue:  'bg-[#eff8ff] border-[#b2ddff] text-[#175cd3]',
    orange:'bg-[#fffaeb] border-[#fedf89] text-[#b54708]',
    gray:  'bg-[#f2f4f7] border-[#e4e7ec] text-[#475467]',
  }[color];
  return (
    <span className={`inline-flex items-center text-[11px] font-medium px-1.5 py-0.5 rounded border ${cls}`}>
      {label}
    </span>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-3">
      <h2 className="text-[15px] font-bold text-[#101828] border-b border-[#e4e7ec] pb-2">{title}</h2>
      {children}
    </section>
  );
}

export function AboutPanel() {
  const freeNoKey = INTEGRATIONS.filter(i => i.tier === 'free' && !i.keyRequired);
  const freeKey   = INTEGRATIONS.filter(i => i.tier === 'free' &&  i.keyRequired);
  const paid      = INTEGRATIONS.filter(i => i.tier === 'paid');

  return (
    <div className="space-y-8 max-w-[960px]">

      {/* Hero */}
      <div className="wb-card p-6">
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 rounded-xl bg-[#101828] flex items-center justify-center shrink-0">
            <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4" />
            </svg>
          </div>
          <div className="flex-1 min-w-0">
            <h1 className="text-xl font-bold text-[#101828] leading-tight">SOC Analyst Toolbox</h1>
            <p className="text-sm text-[#667085] mt-1 leading-relaxed">
              A fully local, privacy-first threat intelligence workbench for SOC analysts and security researchers. Paste an IOC — IP, domain, URL, hash, email, CVE — and instantly pivot across {INTEGRATIONS.length} enrichment providers, {WORKFLOWS.length} investigation workflows, and {61} curated OSINT tools. Nothing is sent to any cloud service except the provider APIs you explicitly configure.
            </p>
            <div className="flex flex-wrap gap-2 mt-3">
              <Badge label={`${INTEGRATIONS.length} Enrichment providers`} color="blue" />
              <Badge label={`${WORKFLOWS.length} Workflows`} color="blue" />
              <Badge label="61 OSINT tool links" color="blue" />
              <Badge label="11 IOC types" color="blue" />
              <Badge label="Local only · No telemetry" color="green" />
            </div>
          </div>
        </div>
      </div>

      {/* Privacy */}
      <div className="wb-card p-4 border-[#fedf89] bg-[#fffaeb]">
        <div className="flex items-start gap-3">
          <svg className="w-4.5 h-4.5 text-[#b54708] shrink-0 mt-0.5" style={{ width: 18, height: 18 }} fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          <div>
            <p className="text-sm font-semibold text-[#b54708]">Privacy model</p>
            <p className="text-xs text-[#92400e] mt-0.5 leading-relaxed">
              All enrichment runs through a <strong>local Node.js backend</strong> (port 3001). API keys are stored in <code className="font-mono text-[11px] bg-[#fef0c7] px-1 py-0.5 rounded">backend/.env</code> and never sent to the frontend. The React frontend never makes direct API calls to external providers. Clickable tool links open in your browser and may submit the IOC to that third-party service — check the <strong>Passive</strong> vs. <strong>Submits IOC</strong> badge on each tool before clicking. AI analysis uses a local Ollama model — no data leaves your machine.
            </p>
          </div>
        </div>
      </div>

      {/* How it works */}
      <Section title="How It Works">
        <div className="wb-card p-4">
          <div className="grid gap-3 sm:grid-cols-2">
            {ARCH_STEPS.map(s => (
              <div key={s.num} className="flex items-start gap-3">
                <div className="w-6 h-6 rounded-full bg-[#1570ef] text-white text-[11px] font-bold flex items-center justify-center shrink-0 mt-0.5">
                  {s.num}
                </div>
                <div>
                  <p className="text-[13px] font-semibold text-[#101828]">{s.title}</p>
                  <p className="text-xs text-[#667085] mt-0.5 leading-relaxed">{s.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </Section>

      {/* Features */}
      <Section title="Features">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map(f => (
            <div key={f.title} className="wb-card p-4">
              <div className="w-8 h-8 rounded-lg bg-[#f2f4f7] text-[#475467] flex items-center justify-center mb-3">
                {f.icon}
              </div>
              <p className="text-[13px] font-semibold text-[#101828] mb-1">{f.title}</p>
              <p className="text-xs text-[#667085] leading-relaxed">{f.desc}</p>
            </div>
          ))}
        </div>
      </Section>

      {/* Supported IOC types */}
      <Section title="Supported IOC Types">
        <div className="wb-card overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[#e4e7ec] bg-[#f9fafb]">
                <th className="text-left px-4 py-2 text-[11px] font-semibold text-[#475467] uppercase tracking-wider">Type</th>
                <th className="text-left px-4 py-2 text-[11px] font-semibold text-[#475467] uppercase tracking-wider">Description</th>
                <th className="text-left px-4 py-2 text-[11px] font-semibold text-[#475467] uppercase tracking-wider">Example</th>
              </tr>
            </thead>
            <tbody>
              {IOC_TYPES.map((t, i) => (
                <tr key={t.type} className={i % 2 === 0 ? 'bg-white' : 'bg-[#fafbfc]'}>
                  <td className="px-4 py-2 font-mono font-semibold text-[#1570ef]">{t.type}</td>
                  <td className="px-4 py-2 text-[#344054]">{t.desc}</td>
                  <td className="px-4 py-2 font-mono text-[#667085]">{t.example}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-xs text-[#667085] px-1">IOC type is detected automatically from the input. Defanged formats (e.g. <code className="font-mono">hxxps://</code>, <code className="font-mono">1[.]2[.]3[.]4</code>) are recognised and refanged before enrichment.</p>
      </Section>

      {/* Investigation Workflows */}
      <Section title="Investigation Workflows">
        <p className="text-xs text-[#667085] px-1">Each workflow activates a pre-selected set of enrichment providers and curated OSINT tool links relevant to that investigation type. Workflows are shown as tiles and are automatically enabled/disabled based on the detected IOC type.</p>
        <div className="grid gap-3 sm:grid-cols-2">
          {WORKFLOWS.map(w => (
            <div key={w.id} className="wb-card p-3.5 flex items-start gap-3">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  <p className="text-[13px] font-semibold text-[#101828]">{w.name}</p>
                  <div className="flex gap-1 flex-wrap">
                    {w.types.map(t => (
                      <span key={t} className="text-[10px] font-mono px-1.5 py-0 rounded bg-[#f2f4f7] border border-[#e4e7ec] text-[#344054]">{t}</span>
                    ))}
                  </div>
                </div>
                <p className="text-xs text-[#667085] leading-relaxed">{w.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </Section>

      {/* Enrichment Integrations */}
      <Section title="Enrichment Integrations">
        <p className="text-xs text-[#667085] px-1">All enrichment runs through the local backend. Configure API keys in the <strong>API Keys</strong> tab. Providers without a key requirement work out of the box.</p>

        {/* Free, no key */}
        <div className="space-y-2">
          <p className="text-[11px] font-semibold text-[#475467] uppercase tracking-wider px-1">Free · No API key required</p>
          <div className="wb-card overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#e4e7ec] bg-[#f9fafb]">
                  <th className="text-left px-4 py-2 text-[11px] font-semibold text-[#475467] uppercase tracking-wider w-40">Provider</th>
                  <th className="text-left px-4 py-2 text-[11px] font-semibold text-[#475467] uppercase tracking-wider w-44">Supports</th>
                  <th className="text-left px-4 py-2 text-[11px] font-semibold text-[#475467] uppercase tracking-wider">What it returns</th>
                </tr>
              </thead>
              <tbody>
                {freeNoKey.map((p, i) => (
                  <tr key={p.id} className={i % 2 === 0 ? 'bg-white' : 'bg-[#fafbfc]'}>
                    <td className="px-4 py-2.5 font-semibold text-[#101828]">{p.name}</td>
                    <td className="px-4 py-2.5">
                      <div className="flex flex-wrap gap-1">
                        {p.supports.map(s => (
                          <span key={s} className="text-[10px] font-mono px-1 py-0 rounded bg-[#f2f4f7] border border-[#e4e7ec] text-[#344054]">{s}</span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-2.5 text-[#667085] leading-relaxed">{p.desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Free, key required */}
        <div className="space-y-2">
          <p className="text-[11px] font-semibold text-[#475467] uppercase tracking-wider px-1">Free · API key required</p>
          <div className="wb-card overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#e4e7ec] bg-[#f9fafb]">
                  <th className="text-left px-4 py-2 text-[11px] font-semibold text-[#475467] uppercase tracking-wider w-40">Provider</th>
                  <th className="text-left px-4 py-2 text-[11px] font-semibold text-[#475467] uppercase tracking-wider w-44">Supports</th>
                  <th className="text-left px-4 py-2 text-[11px] font-semibold text-[#475467] uppercase tracking-wider">What it returns</th>
                </tr>
              </thead>
              <tbody>
                {freeKey.map((p, i) => (
                  <tr key={p.id} className={i % 2 === 0 ? 'bg-white' : 'bg-[#fafbfc]'}>
                    <td className="px-4 py-2.5 font-semibold text-[#101828]">{p.name}</td>
                    <td className="px-4 py-2.5">
                      <div className="flex flex-wrap gap-1">
                        {p.supports.map(s => (
                          <span key={s} className="text-[10px] font-mono px-1 py-0 rounded bg-[#f2f4f7] border border-[#e4e7ec] text-[#344054]">{s}</span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-2.5 text-[#667085] leading-relaxed">{p.desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Paid / limited */}
        <div className="space-y-2">
          <p className="text-[11px] font-semibold text-[#475467] uppercase tracking-wider px-1">Paid or limited free tier</p>
          <div className="wb-card overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#e4e7ec] bg-[#f9fafb]">
                  <th className="text-left px-4 py-2 text-[11px] font-semibold text-[#475467] uppercase tracking-wider w-40">Provider</th>
                  <th className="text-left px-4 py-2 text-[11px] font-semibold text-[#475467] uppercase tracking-wider w-44">Supports</th>
                  <th className="text-left px-4 py-2 text-[11px] font-semibold text-[#475467] uppercase tracking-wider">What it returns</th>
                </tr>
              </thead>
              <tbody>
                {paid.map((p, i) => (
                  <tr key={p.id} className={i % 2 === 0 ? 'bg-white' : 'bg-[#fafbfc]'}>
                    <td className="px-4 py-2.5 font-semibold text-[#101828]">{p.name}</td>
                    <td className="px-4 py-2.5">
                      <div className="flex flex-wrap gap-1">
                        {p.supports.map(s => (
                          <span key={s} className="text-[10px] font-mono px-1 py-0 rounded bg-[#f2f4f7] border border-[#e4e7ec] text-[#344054]">{s}</span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-2.5 text-[#667085] leading-relaxed">{p.desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </Section>

      {/* Getting started */}
      <Section title="Getting Started">
        <div className="wb-card p-4 space-y-4">
          <div>
            <p className="text-[13px] font-semibold text-[#101828] mb-1">1 — Start the backend</p>
            <pre className="bg-[#101828] text-[#e4e7ec] text-[12px] font-mono rounded-lg px-4 py-3 overflow-x-auto">
              {`cd backend\nnpm install\nnpm run dev`}
            </pre>
            <p className="text-xs text-[#667085] mt-1.5">The backend starts on <code className="font-mono text-[11px]">http://localhost:3001</code>. The frontend polls the health endpoint every 30 seconds and shows online/offline status.</p>
          </div>

          <div>
            <p className="text-[13px] font-semibold text-[#101828] mb-1">2 — Configure API keys</p>
            <p className="text-xs text-[#667085] leading-relaxed">Go to the <strong>API Keys</strong> tab and paste your credentials. Keys are saved to <code className="font-mono text-[11px] bg-[#f2f4f7] px-1 py-0.5 rounded">backend/.env</code>. The backend reloads the config without restarting. You can also edit the <code className="font-mono text-[11px] bg-[#f2f4f7] px-1 py-0.5 rounded">.env</code> file directly.</p>
          </div>

          <div>
            <p className="text-[13px] font-semibold text-[#101828] mb-1">3 — (Optional) Enable AI analysis</p>
            <pre className="bg-[#101828] text-[#e4e7ec] text-[12px] font-mono rounded-lg px-4 py-3 overflow-x-auto">
              {`# Install Ollama from https://ollama.com\nollama pull qwen2.5\n# or: ollama pull llama3.2`}
            </pre>
            <p className="text-xs text-[#667085] mt-1.5">Any Ollama model works. The backend auto-detects running models. The AI analysis panel lets you pick the model and runs the prompt entirely locally.</p>
          </div>

          <div>
            <p className="text-[13px] font-semibold text-[#101828] mb-1">4 — Start the frontend</p>
            <pre className="bg-[#101828] text-[#e4e7ec] text-[12px] font-mono rounded-lg px-4 py-3 overflow-x-auto">
              {`npm install\nnpm run dev`}
            </pre>
            <p className="text-xs text-[#667085] mt-1.5">Opens at <code className="font-mono text-[11px]">http://localhost:5173</code>. The app is a local SPA — no build step needed during development.</p>
          </div>
        </div>
      </Section>

      {/* Tech stack */}
      <Section title="Technical Stack">
        <div className="wb-card p-4">
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            {[
              { label: 'Frontend', value: 'React 18 + TypeScript + Vite' },
              { label: 'Styling', value: 'Tailwind CSS' },
              { label: 'Backend', value: 'Node.js + Express + TypeScript' },
              { label: 'AI', value: 'Ollama (local LLM)' },
              { label: 'Storage', value: 'In-memory cache + .env file' },
              { label: 'Package manager', value: 'npm' },
            ].map(r => (
              <div key={r.label}>
                <p className="text-[11px] font-semibold text-[#98a2b3] uppercase tracking-wider mb-0.5">{r.label}</p>
                <p className="text-[13px] text-[#101828]">{r.value}</p>
              </div>
            ))}
          </div>
        </div>
      </Section>

    </div>
  );
}
