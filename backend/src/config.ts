import { config as loadDotenv } from 'dotenv';

loadDotenv();


function envStr(key: string, fallback = ''): string {
  return process.env[key] ?? fallback;
}

function envInt(key: string, fallback: number): number {
  const v = process.env[key];
  if (!v) return fallback;
  const n = parseInt(v, 10);
  return isNaN(n) ? fallback : n;
}

function envBool(key: string, fallback: boolean): boolean {
  const v = process.env[key];
  if (!v) return fallback;
  return v.toLowerCase() === 'true' || v === '1';
}

export interface Config {
  greynoise: { apiKey: string };
  abuseipdb: { apiKey: string };
  ipinfo: { token: string };
  virustotal: { apiKey: string };
  urlscan: { apiKey: string };
  shodan: { apiKey: string };
  censys: { apiToken: string };
  whoisxmlapi: { apiKey: string };
  otx: { apiKey: string };
  pulsedive: { apiKey: string };
  safebrowsing: { apiKey: string };
  hibp: { apiKey: string };
  hybridanalysis: { apiKey: string };
  threatfox: { apiKey: string };
  urlhaus: { apiKey: string };
  hunter: { apiKey: string };
  dnsdumpster: { apiKey: string };
  port: number;
  cacheTtlMinutes: number;
  enableUrlSubmission: boolean;
  enableHighRiskEnrichment: boolean;
  logLevel: string;
  configuredProviders: string[];
}

const greynoiseKey = envStr('GREYNOISE_API_KEY');
const abuseipdbKey = envStr('ABUSEIPDB_API_KEY');
const ipinfoToken = envStr('IPINFO_TOKEN');
const virustotalKey = envStr('VIRUSTOTAL_API_KEY');
const urlscanKey = envStr('URLSCAN_API_KEY');
const shodanKey = envStr('SHODAN_API_KEY');
const censysToken = envStr('CENSYS_API_TOKEN');
const whoisxmlapiKey = envStr('WHOISXMLAPI_KEY');
const otxKey = envStr('OTX_API_KEY');
const pulsediveKey = envStr('PULSEDIVE_API_KEY');
const safebrowsingKey = envStr('GOOGLE_SAFE_BROWSING_KEY');
const hibpKey = envStr('HIBP_API_KEY');
const hybridanalysisKey = envStr('HYBRID_ANALYSIS_KEY');
const threatfoxKey = envStr('THREATFOX_API_KEY');
const urlhausKey = envStr('URLHAUS_API_KEY');
const hunterKey = envStr('HUNTER_API_KEY');
const dnsdumpsterKey = envStr('DNSDUMPSTER_API_KEY');

const configuredProviders: string[] = [];
if (greynoiseKey) configuredProviders.push('greynoise');
if (abuseipdbKey) configuredProviders.push('abuseipdb');
if (ipinfoToken) configuredProviders.push('ipinfo');
if (virustotalKey) configuredProviders.push('virustotal');
if (urlscanKey) configuredProviders.push('urlscan');
if (shodanKey) configuredProviders.push('shodan');
if (censysToken) configuredProviders.push('censys');
if (whoisxmlapiKey) configuredProviders.push('whoisxmlapi');
if (otxKey) configuredProviders.push('otx');
if (pulsediveKey) configuredProviders.push('pulsedive');
if (safebrowsingKey) configuredProviders.push('safebrowsing');
if (hibpKey) configuredProviders.push('hibp');
if (hybridanalysisKey) configuredProviders.push('hybridanalysis');
if (threatfoxKey) configuredProviders.push('threatfox');
if (urlhausKey) configuredProviders.push('urlhaus');
if (hunterKey) configuredProviders.push('hunter');
if (dnsdumpsterKey) configuredProviders.push('dnsdumpster');

export const config: Config = {
  greynoise: { apiKey: greynoiseKey },
  abuseipdb: { apiKey: abuseipdbKey },
  ipinfo: { token: ipinfoToken },
  virustotal: { apiKey: virustotalKey },
  urlscan: { apiKey: urlscanKey },
  shodan: { apiKey: shodanKey },
  censys: { apiToken: censysToken },
  whoisxmlapi: { apiKey: whoisxmlapiKey },
  otx: { apiKey: otxKey },
  pulsedive: { apiKey: pulsediveKey },
  safebrowsing: { apiKey: safebrowsingKey },
  hibp: { apiKey: hibpKey },
  hybridanalysis: { apiKey: hybridanalysisKey },
  threatfox: { apiKey: threatfoxKey },
  urlhaus: { apiKey: urlhausKey },
  hunter: { apiKey: hunterKey },
  dnsdumpster: { apiKey: dnsdumpsterKey },
  port: envInt('PORT', 8787),
  cacheTtlMinutes: envInt('CACHE_TTL_MINUTES', 60),
  enableUrlSubmission: envBool('ENABLE_URL_SUBMISSION', false),
  enableHighRiskEnrichment: envBool('ENABLE_HIGH_RISK_ENRICHMENT', false),
  logLevel: envStr('LOG_LEVEL', 'info'),
  configuredProviders,
};

/**
 * Re-derives the config from process.env in place.
 * Call this after writing new API keys to the .env file so enrichment
 * picks up the new values without restarting the server.
 */
export function reloadConfig(): void {
  config.greynoise.apiKey = envStr('GREYNOISE_API_KEY');
  config.abuseipdb.apiKey = envStr('ABUSEIPDB_API_KEY');
  config.ipinfo.token = envStr('IPINFO_TOKEN');
  config.virustotal.apiKey = envStr('VIRUSTOTAL_API_KEY');
  config.urlscan.apiKey = envStr('URLSCAN_API_KEY');
  config.shodan.apiKey = envStr('SHODAN_API_KEY');
  config.censys.apiToken = envStr('CENSYS_API_TOKEN');
  config.whoisxmlapi.apiKey = envStr('WHOISXMLAPI_KEY');

  // Rebuild configuredProviders in place
  config.configuredProviders.length = 0;
  if (config.greynoise.apiKey) config.configuredProviders.push('greynoise');
  if (config.abuseipdb.apiKey) config.configuredProviders.push('abuseipdb');
  if (config.ipinfo.token) config.configuredProviders.push('ipinfo');
  if (config.virustotal.apiKey) config.configuredProviders.push('virustotal');
  if (config.urlscan.apiKey) config.configuredProviders.push('urlscan');
  if (config.shodan.apiKey) config.configuredProviders.push('shodan');
  if (config.censys.apiToken) config.configuredProviders.push('censys');
  if (config.whoisxmlapi.apiKey) config.configuredProviders.push('whoisxmlapi');
  config.otx.apiKey = envStr('OTX_API_KEY');
  config.pulsedive.apiKey = envStr('PULSEDIVE_API_KEY');
  config.safebrowsing.apiKey = envStr('GOOGLE_SAFE_BROWSING_KEY');
  config.hibp.apiKey = envStr('HIBP_API_KEY');
  config.hybridanalysis.apiKey = envStr('HYBRID_ANALYSIS_KEY');
  if (config.otx.apiKey) config.configuredProviders.push('otx');
  if (config.pulsedive.apiKey) config.configuredProviders.push('pulsedive');
  if (config.safebrowsing.apiKey) config.configuredProviders.push('safebrowsing');
  if (config.hibp.apiKey) config.configuredProviders.push('hibp');
  if (config.hybridanalysis.apiKey) config.configuredProviders.push('hybridanalysis');
  config.threatfox.apiKey = envStr('THREATFOX_API_KEY');
  if (config.threatfox.apiKey) config.configuredProviders.push('threatfox');
  config.urlhaus.apiKey = envStr('URLHAUS_API_KEY');
  if (config.urlhaus.apiKey) config.configuredProviders.push('urlhaus');
  config.hunter.apiKey = envStr('HUNTER_API_KEY');
  if (config.hunter.apiKey) config.configuredProviders.push('hunter');
  config.dnsdumpster.apiKey = envStr('DNSDUMPSTER_API_KEY');
  if (config.dnsdumpster.apiKey) config.configuredProviders.push('dnsdumpster');
}
