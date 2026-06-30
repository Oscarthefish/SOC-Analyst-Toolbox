import type { AdapterFn } from '../types.js';
import { cisakev } from './cisakev.js';
import { dns } from './dns.js';
import { crtsh } from './crtsh.js';
import { greynoise } from './greynoise.js';
import { abuseipdb } from './abuseipdb.js';
import { ipinfo } from './ipinfo.js';
import { virustotal } from './virustotal.js';
import { urlscan } from './urlscan.js';
import { shodan } from './shodan.js';
import { censys } from './censys.js';
import { whois } from './whois.js';
import { malwarebazaar } from './malwarebazaar.js';
import { urlhaus } from './urlhaus.js';
import { threatfox } from './threatfox.js';
import { bgpview } from './bgpview.js';
import { otx } from './otx.js';
import { pulsedive } from './pulsedive.js';
import { safebrowsing } from './safebrowsing.js';
import { hibp } from './hibp.js';
import { hybridanalysis } from './hybridanalysis.js';
import { ipapi } from './ipapi.js';
import { torproject } from './torproject.js';
import { ransomwarelive } from './ransomwarelive.js';
import { hunter } from './hunter.js';
import { wayback } from './wayback.js';
import { dnsdumpster } from './dnsdumpster.js';

export const adapters: Record<string, AdapterFn> = {
  cisakev,
  dns,
  crtsh,
  greynoise,
  abuseipdb,
  ipinfo,
  virustotal,
  urlscan,
  shodan,
  censys,
  whois,
  malwarebazaar,
  urlhaus,
  threatfox,
  bgpview,
  otx,
  pulsedive,
  safebrowsing,
  hibp,
  hybridanalysis,
  ipapi,
  torproject,
  ransomwarelive,
  hunter,
  wayback,
  dnsdumpster,
};

export const PROVIDER_NAMES: Record<string, string> = {
  cisakev: 'CISA KEV',
  dns: 'DNS Resolution',
  crtsh: 'crt.sh',
  greynoise: 'GreyNoise',
  abuseipdb: 'AbuseIPDB',
  ipinfo: 'IPinfo',
  virustotal: 'VirusTotal',
  urlscan: 'urlscan.io',
  shodan: 'Shodan',
  censys: 'Censys',
  whois: 'WHOIS',
  malwarebazaar: 'MalwareBazaar',
  urlhaus: 'URLhaus',
  threatfox: 'ThreatFox',
  bgpview: 'RIPE Stat',
  otx: 'AlienVault OTX',
  pulsedive: 'Pulsedive',
  safebrowsing: 'Google Safe Browsing',
  hibp: 'HaveIBeenPwned',
  hybridanalysis: 'Hybrid Analysis',
  ipapi: 'ip-api.com',
  torproject: 'Tor Project (Onionoo)',
  ransomwarelive: 'Ransomware.live',
  hunter: 'Hunter.io',
  wayback: 'Wayback Machine',
  dnsdumpster: 'DNSDumpster',
};
