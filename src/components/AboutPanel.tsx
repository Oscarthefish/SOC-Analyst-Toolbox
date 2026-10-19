import { useState } from 'react';
import { storageUsage, clearAllLocalData } from '../lib/storage';
import { IocTypeChip } from './IocTypeChip';
import toolsData from '../data/tools.json';

const TOOL_COUNT = (toolsData as unknown[]).length;

/** About-page "supports" labels → indicator type ids, for the shared colour chips */
const TYPE_ID: Record<string, string> = {
  IPv4: 'ipv4', IPv6: 'ipv6', Domain: 'domain', URL: 'url', MD5: 'md5', SHA1: 'sha1', SHA256: 'sha256',
  Email: 'email', ASN: 'asn', CIDR: 'cidr', CVE: 'cve', 'Email header': 'headers',
};
const Chip = ({ label }: { label: string }) => <IocTypeChip type={TYPE_ID[label] ?? label} size="sm" />;

const TONES = [
  'bg-c1-bg text-c1-fg', 'bg-c2-bg text-c2-fg', 'bg-c3-bg text-c3-fg', 'bg-c4-bg text-c4-fg', 'bg-c5-bg text-c5-fg',
];
const STEP_TONES = ['bg-c1', 'bg-c2', 'bg-c3', 'bg-c4', 'bg-c5', 'bg-c1', 'bg-c2'];
const INTEGRATIONS = [
  // No key required
  { name: 'DNS Resolution',      id: 'dns',            tier: 'free',  keyRequired: false, supports: ['Domain'],                            desc: 'Node.js built-in resolver. Returns IPv4/IPv6 records and pivot links to each resolved IP.' },
  { name: 'RIPE Stat',           id: 'bgpview',        tier: 'free',  keyRequired: false, supports: ['IPv4', 'IPv6', 'ASN', 'CIDR'],       desc: 'BGP routing and prefix data from RIPE NCC. ASN holder, country, and announcement status.' },
  { name: 'CISA KEV',            id: 'cisakev',        tier: 'free',  keyRequired: false, supports: ['CVE'],                               desc: 'CISA Known Exploited Vulnerabilities catalogue. Flags CVEs actively exploited in the wild.' },
  { name: 'Ransomware.live',     id: 'ransomwarelive', tier: 'free',  keyRequired: false, supports: ['Domain'],                            desc: 'Public ransomware victim listing. Checks if a domain appears in known ransomware group postings.' },
  { name: 'crt.sh',              id: 'crtsh',          tier: 'free',  keyRequired: false, supports: ['Domain'],                            desc: 'Certificate transparency logs. Extracts SANs from recent TLS certificates to pivot to related subdomains.' },
  { name: 'Wayback Machine',     id: 'wayback',        tier: 'free',  keyRequired: false, supports: ['Domain'],                            desc: 'Internet Archive CDX API. Returns first and most recent snapshot dates — useful for detecting re-registered domains.' },
  { name: 'Tor Project (Onionoo)',id: 'torproject',    tier: 'free',  keyRequired: false, supports: ['IPv4', 'IPv6'],                      desc: 'Onionoo relay database. Identifies whether an IP is a Tor exit node, guard, or relay.' },
  { name: 'ip-api',              id: 'ipapi',          tier: 'paid',  keyRequired: true,  supports: ['IPv4', 'IPv6'],                      desc: 'IP geolocation, ISP and proxy/hosting flags. Off by default: the free tier is plain HTTP. Use a Pro key (HTTPS) or set IPAPI_ALLOW_HTTP=true.' },
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
    desc: 'Paste any IOC and the tool auto-detects the type. Choose a workflow and run enrichment across multiple providers simultaneously. Results include a severity verdict, a relationship graph, a provider-by-provider breakdown, pivot links and an optional written summary from a local LLM.',
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
    desc: 'Submit up to 50 IOCs at once. The toolbox runs 5 concurrent enrichment jobs, updates a live results table, and charts the severity mix as results arrive. One click pivots any result into a full investigation.',
  },
  {
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 2a10 10 0 100 20A10 10 0 0012 2z" />
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3" />
      </svg>
    ),
    title: 'Local LLM summary',
    desc: 'Optional. A local Ollama model turns the provider results into a short written assessment. It is asked to name its sources, and is re-prompted once if it cites fewer than two. Nothing leaves your machine.',
  },
  {
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101" />
        <path strokeLinecap="round" strokeLinejoin="round" d="M14.828 14.828a4 4 0 015.656 0l4-4a4 4 0 01-5.656-5.656l-1.102 1.101" />
      </svg>
    ),
    title: 'Relationship graph',
    desc: 'ASN, operator, country, registration, open ports, resolved IPs, certificate names and threat labels, merged across providers so you can see which facts several sources agree on. Hosts and ASNs pivot into a new investigation.',
  },
  {
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
        <circle cx="12" cy="12" r="8" /><circle cx="12" cy="12" r="2.5" /><path strokeLinecap="round" d="M12 2v4M12 18v4M2 12h4M18 12h4" />
      </svg>
    ),
    title: 'ATT&CK and hunt queries',
    desc: 'Techniques linked to an indicator are shown with their evidence (reported by a provider, inferred from a label, or from the workflow). The Hunt page turns indicators and techniques into KQL for Sentinel or Defender XDR, or SPL for Splunk.',
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
    title: 'Threat feed',
    desc: 'A briefing of recent CISA KEV additions and Ransomware.live victim posts, with a 30-day timeline, the most active groups and the most-exploited vendors. Pulsedive high-risk indicators are available on a second tab.',
  },
];

const ARCH_STEPS = [
  { num: '1', title: 'Classify', desc: 'Paste an indicator. The browser detects its type (defanged input is refanged first) and shows the workflows that apply.' },
  { num: '2', title: 'Choose a workflow', desc: 'Optional. A workflow adds its pivot tools, analyst checklist and context for the written summary.' },
  { num: '3', title: 'Enrich', desc: 'The browser calls the local backend (port 8787, proxied by Vite). It queries every provider that supports the indicator type at once and streams results back as they arrive.' },
  { num: '4', title: 'Cache', desc: 'Provider results are cached on disk per provider (10 minutes for DNS up to 24 hours for WHOIS), so repeat lookups don’t spend API quota. Bypass cache forces fresh queries.' },
  { num: '5', title: 'Score', desc: 'The backend works out an overall severity from sources that give a risk opinion, and flags where sources contradict each other.' },
  { num: '6', title: 'Summarise', desc: 'Optional. If Ollama is running, a local model writes a short assessment. Nothing leaves your machine.' },
  { num: '7', title: 'Review', desc: 'The verdict, relationship graph, provider verdicts and conflicts are shown together, ready to save as a case.' },
];

function formatBytes(n: number): string {
  return n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1024 / 1024).toFixed(1)} MB`;
}

/** What this app keeps in the browser, with a two-step "clear everything". */
function LocalData() {
  const [usage, setUsage] = useState(() => storageUsage());
  const [confirming, setConfirming] = useState(false);
  const total = usage.reduce((n, u) => n + u.bytes, 0);

  return (
    <div className="wb-card overflow-hidden">
      {usage.length === 0 ? (
        <p className="px-4 py-4 text-xs text-fg-3">Nothing is stored in this browser.</p>
      ) : (
        <table className="w-full text-left text-[13px]">
          <tbody className="divide-y divide-line-soft">
            {usage.map(u => (
              <tr key={u.key}>
                <td className="px-4 py-2 text-fg-2">{u.description}</td>
                <td className="px-4 py-2 font-mono text-[11px] text-fg-4">{u.key}</td>
                <td className="px-4 py-2 text-right text-xs text-fg-3 tabular-nums">{formatBytes(u.bytes)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="flex flex-wrap items-center gap-2 px-4 py-3 border-t border-line bg-inset">
        <p className="text-xs text-fg-3 mr-auto">
          Stored unencrypted in this browser only{total > 0 && ` · ${formatBytes(total)}`}. API keys are never stored here.
        </p>
        {confirming ? (
          <>
            <span className="text-xs text-danger-fg">Delete all cases, history and preferences?</span>
            <button
              onClick={() => { clearAllLocalData(); setUsage(storageUsage()); setConfirming(false); window.location.reload(); }}
              className="h-7 px-2.5 text-xs font-medium rounded-md bg-danger text-white"
            >
              Delete everything
            </button>
            <button onClick={() => setConfirming(false)} className="h-7 px-2.5 text-xs rounded-md border border-line bg-surface text-fg-2">Cancel</button>
          </>
        ) : (
          <button
            onClick={() => setConfirming(true)}
            disabled={usage.length === 0}
            className="h-7 px-2.5 text-xs font-medium rounded-md border border-line bg-surface text-fg-2 hover:border-danger-line hover:text-danger-fg disabled:opacity-40"
          >
            Clear local data…
          </button>
        )}
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-3">
      <h2 className="text-[15px] font-bold text-fg-1 border-b border-line pb-2">{title}</h2>
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
      <div className="rounded-2xl bg-rail p-6 text-rail-fg">
        <h1 className="text-xl font-semibold text-rail-fg-1 leading-tight">SOC Analyst Toolbox</h1>
        <p className="text-sm mt-1.5 leading-relaxed max-w-[60ch]">
          A local workbench for triaging indicators. Paste an IP, domain, URL, hash, email, ASN, CIDR or CVE, enrich it across the providers you’ve set up, and pivot to external tools. Nothing goes to a cloud service except the provider APIs you configure and the tool links you choose to open.
        </p>
        <dl className="mt-5 grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { k: 'Enrichment providers', v: INTEGRATIONS.length },
            { k: 'Workflows', v: WORKFLOWS.length },
            { k: 'Pivot tools', v: TOOL_COUNT },
            { k: 'Indicator types', v: IOC_TYPES.length },
          ].map(x => (
            <div key={x.k} className="rounded-lg bg-rail-hover border border-rail-line px-3 py-2.5">
              <dt className="text-[11px] text-rail-fg">{x.k}</dt>
              <dd className="text-[22px] font-semibold text-rail-fg-1 tabular-nums leading-tight">{x.v}</dd>
            </div>
          ))}
        </dl>
      </div>

      {/* Privacy */}
      <div className="wb-card p-4 border-l-[3px] border-l-ok">
        <div className="flex items-start gap-3">
          <span className="w-8 h-8 rounded-full grid place-items-center bg-ok-bg text-ok-fg shrink-0" aria-hidden>
            <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={1.8} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </span>
          <div>
            <p className="text-sm font-semibold text-fg-1">Privacy model</p>
            <ul className="mt-1 space-y-1 text-xs text-fg-2 leading-relaxed list-disc pl-4">
              <li>All enrichment goes through the <strong>local backend</strong>; the browser never calls providers directly.</li>
              <li>API keys live in <code className="font-mono text-[11px] bg-raised px-1 py-0.5 rounded">backend/.env</code> and are never sent to the browser.</li>
              <li>Pivot tool links open in your browser and may send the indicator to that service. Check each tool’s <strong>Passive</strong>, <strong>Submits IOC</strong> or <strong>Public</strong> label first.</li>
              <li>The written summary uses a local Ollama model, so no data leaves your machine.</li>
            </ul>
          </div>
        </div>
      </div>

      {/* How it works */}
      <Section title="How It Works">
        <ol className="wb-card p-4 sm:p-5">
          {ARCH_STEPS.map((s, i) => (
            <li key={s.num} className="relative flex items-start gap-3.5 pb-4 last:pb-0">
              {i < ARCH_STEPS.length - 1 && <span className="absolute left-[13px] top-7 bottom-0 w-[2px] bg-line" aria-hidden />}
              <span className={`relative w-7 h-7 rounded-full text-on-ramp text-[12px] font-semibold grid place-items-center shrink-0 ${STEP_TONES[i]}`}>
                {s.num}
              </span>
              <div className="pt-0.5">
                <p className="text-[13px] font-semibold text-fg-1">{s.title}</p>
                <p className="text-xs text-fg-3 mt-0.5 leading-relaxed max-w-[70ch]">{s.desc}</p>
              </div>
            </li>
          ))}
        </ol>
      </Section>

      {/* Features */}
      <Section title="Features">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map((f, i) => (
            <div key={f.title} className="wb-card p-4">
              <div className={`w-9 h-9 rounded-full flex items-center justify-center mb-3 ${TONES[i % TONES.length]}`}>
                {f.icon}
              </div>
              <p className="text-[13px] font-semibold text-fg-1 mb-1">{f.title}</p>
              <p className="text-xs text-fg-3 leading-relaxed">{f.desc}</p>
            </div>
          ))}
        </div>
      </Section>

      {/* Supported IOC types */}
      <Section title="Supported IOC Types">
        <div className="wb-card overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-line bg-inset">
                <th className="text-left px-4 py-2 text-[11px] font-semibold text-fg-2 uppercase tracking-wider">Type</th>
                <th className="text-left px-4 py-2 text-[11px] font-semibold text-fg-2 uppercase tracking-wider">Description</th>
                <th className="text-left px-4 py-2 text-[11px] font-semibold text-fg-2 uppercase tracking-wider">Example</th>
              </tr>
            </thead>
            <tbody>
              {IOC_TYPES.map((t, i) => (
                <tr key={t.type} className={i % 2 === 0 ? 'bg-surface' : 'bg-inset'}>
                  <td className="px-4 py-2"><Chip label={t.type} /></td>
                  <td className="px-4 py-2 text-fg-2">{t.desc}</td>
                  <td className="px-4 py-2 font-mono text-fg-3">{t.example}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-xs text-fg-3 px-1">IOC type is detected automatically from the input. Defanged formats (e.g. <code className="font-mono">hxxps://</code>, <code className="font-mono">1[.]2[.]3[.]4</code>) are recognised and refanged before enrichment.</p>
      </Section>

      {/* Investigation Workflows */}
      <Section title="Investigation Workflows">
        <p className="text-xs text-fg-3 px-1">Each workflow activates a pre-selected set of enrichment providers and curated OSINT tool links relevant to that investigation type. Only the workflows that apply to the detected indicator type are offered.</p>
        <div className="grid gap-3 sm:grid-cols-2">
          {WORKFLOWS.map(w => (
            <div key={w.id} className="wb-card p-3.5 flex items-start gap-3">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  <p className="text-[13px] font-semibold text-fg-1">{w.name}</p>
                  <div className="flex gap-1 flex-wrap">
                    {w.types.map(t => <Chip key={t} label={t} />)}
                  </div>
                </div>
                <p className="text-xs text-fg-3 leading-relaxed">{w.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </Section>

      {/* Enrichment Integrations */}
      <Section title="Enrichment Integrations">
        <p className="text-xs text-fg-3 px-1">All enrichment runs through the local backend. Add API keys on the <strong>Integrations</strong> page. Providers without a key requirement work out of the box.</p>

        {/* Free, no key */}
        <div className="space-y-2">
          <p className="text-[11px] font-semibold text-fg-2 uppercase tracking-wider px-1">Free · No API key required</p>
          <div className="wb-card overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-line bg-inset">
                  <th className="text-left px-4 py-2 text-[11px] font-semibold text-fg-2 uppercase tracking-wider w-40">Provider</th>
                  <th className="text-left px-4 py-2 text-[11px] font-semibold text-fg-2 uppercase tracking-wider w-44">Supports</th>
                  <th className="text-left px-4 py-2 text-[11px] font-semibold text-fg-2 uppercase tracking-wider">What it returns</th>
                </tr>
              </thead>
              <tbody>
                {freeNoKey.map((p, i) => (
                  <tr key={p.id} className={i % 2 === 0 ? 'bg-surface' : 'bg-inset'}>
                    <td className="px-4 py-2.5 font-semibold text-fg-1">{p.name}</td>
                    <td className="px-4 py-2.5">
                      <div className="flex flex-wrap gap-1">
                        {p.supports.map(s => <Chip key={s} label={s} />)}
                      </div>
                    </td>
                    <td className="px-4 py-2.5 text-fg-3 leading-relaxed">{p.desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Free, key required */}
        <div className="space-y-2">
          <p className="text-[11px] font-semibold text-fg-2 uppercase tracking-wider px-1">Free · API key required</p>
          <div className="wb-card overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-line bg-inset">
                  <th className="text-left px-4 py-2 text-[11px] font-semibold text-fg-2 uppercase tracking-wider w-40">Provider</th>
                  <th className="text-left px-4 py-2 text-[11px] font-semibold text-fg-2 uppercase tracking-wider w-44">Supports</th>
                  <th className="text-left px-4 py-2 text-[11px] font-semibold text-fg-2 uppercase tracking-wider">What it returns</th>
                </tr>
              </thead>
              <tbody>
                {freeKey.map((p, i) => (
                  <tr key={p.id} className={i % 2 === 0 ? 'bg-surface' : 'bg-inset'}>
                    <td className="px-4 py-2.5 font-semibold text-fg-1">{p.name}</td>
                    <td className="px-4 py-2.5">
                      <div className="flex flex-wrap gap-1">
                        {p.supports.map(s => <Chip key={s} label={s} />)}
                      </div>
                    </td>
                    <td className="px-4 py-2.5 text-fg-3 leading-relaxed">{p.desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Paid / limited */}
        <div className="space-y-2">
          <p className="text-[11px] font-semibold text-fg-2 uppercase tracking-wider px-1">Paid or limited free tier</p>
          <div className="wb-card overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-line bg-inset">
                  <th className="text-left px-4 py-2 text-[11px] font-semibold text-fg-2 uppercase tracking-wider w-40">Provider</th>
                  <th className="text-left px-4 py-2 text-[11px] font-semibold text-fg-2 uppercase tracking-wider w-44">Supports</th>
                  <th className="text-left px-4 py-2 text-[11px] font-semibold text-fg-2 uppercase tracking-wider">What it returns</th>
                </tr>
              </thead>
              <tbody>
                {paid.map((p, i) => (
                  <tr key={p.id} className={i % 2 === 0 ? 'bg-surface' : 'bg-inset'}>
                    <td className="px-4 py-2.5 font-semibold text-fg-1">{p.name}</td>
                    <td className="px-4 py-2.5">
                      <div className="flex flex-wrap gap-1">
                        {p.supports.map(s => <Chip key={s} label={s} />)}
                      </div>
                    </td>
                    <td className="px-4 py-2.5 text-fg-3 leading-relaxed">{p.desc}</td>
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
            <p className="text-[13px] font-semibold text-fg-1 mb-1">1 — Install and start</p>
            <pre className="bg-inset border border-line text-fg-2 text-[12px] font-mono rounded-lg px-4 py-3 overflow-x-auto">
              {`npm install\nnpm run backend:install\nnpm run dev`}
            </pre>
            <p className="text-xs text-fg-3 mt-1.5"><code className="font-mono text-[11px]">npm run dev</code> starts the backend on port 8787 and the app on <code className="font-mono text-[11px]">http://localhost:5173</code>. The sidebar shows whether the backend is reachable; it is checked every 30 seconds.</p>
          </div>

          <div>
            <p className="text-[13px] font-semibold text-fg-1 mb-1">2 — Configure API keys</p>
            <p className="text-xs text-fg-3 leading-relaxed">Open the <strong>Integrations</strong> page and paste your credentials. Keys are saved to <code className="font-mono text-[11px] bg-raised px-1 py-0.5 rounded">backend/.env</code>. The backend reloads the config without restarting. You can also edit the <code className="font-mono text-[11px] bg-raised px-1 py-0.5 rounded">.env</code> file directly.</p>
          </div>

          <div>
            <p className="text-[13px] font-semibold text-fg-1 mb-1">3 — (Optional) Enable the written summary</p>
            <pre className="bg-inset border border-line text-fg-2 text-[12px] font-mono rounded-lg px-4 py-3 overflow-x-auto">
              {`# Install Ollama from https://ollama.com\nollama pull qwen2.5\n# or: ollama pull llama3.2`}
            </pre>
            <p className="text-xs text-fg-3 mt-1.5">The backend uses <code className="font-mono text-[11px]">qwen2.5</code> by default and picks whichever installed variant matches (for example <code className="font-mono text-[11px]">qwen2.5:7b</code>). If Ollama isn’t running, analysis still works without the written summary.</p>
          </div>

        </div>
      </Section>

      <Section title="Data in This Browser">
        <LocalData />
      </Section>

      {/* Tech stack */}
      <Section title="Technical Stack">
        <div className="wb-card p-4">
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            {[
              { label: 'Frontend', value: 'React 19 + TypeScript + Vite' },
              { label: 'Styling', value: 'Tailwind CSS 4' },
              { label: 'Backend', value: 'Node.js 20+ + Express 5 + TypeScript' },
              { label: 'AI', value: 'Ollama (local LLM, optional)' },
              { label: 'Storage', value: 'Browser localStorage; backend file cache + .env' },
              { label: 'Tests', value: 'Vitest' },
            ].map(r => (
              <div key={r.label}>
                <p className="text-[11px] font-semibold text-fg-4 uppercase tracking-wider mb-0.5">{r.label}</p>
                <p className="text-[13px] text-fg-1">{r.value}</p>
              </div>
            ))}
          </div>
        </div>
      </Section>

    </div>
  );
}
