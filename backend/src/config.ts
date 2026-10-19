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

/**
 * Single source of truth for provider credentials: which env var holds the key,
 * and which field adapters read it from (`config.<provider>.<field>`).
 * The key-management API allowlist and configuredProviders are derived from this.
 */
export const PROVIDER_KEYS = [
  { provider: 'greynoise',      env: 'GREYNOISE_API_KEY',        field: 'apiKey' },
  { provider: 'abuseipdb',      env: 'ABUSEIPDB_API_KEY',        field: 'apiKey' },
  { provider: 'ipinfo',         env: 'IPINFO_TOKEN',             field: 'token' },
  { provider: 'virustotal',     env: 'VIRUSTOTAL_API_KEY',       field: 'apiKey' },
  { provider: 'urlscan',        env: 'URLSCAN_API_KEY',          field: 'apiKey' },
  { provider: 'shodan',         env: 'SHODAN_API_KEY',           field: 'apiKey' },
  { provider: 'censys',         env: 'CENSYS_API_TOKEN',         field: 'apiToken' },
  { provider: 'whoisxmlapi',    env: 'WHOISXMLAPI_KEY',          field: 'apiKey' },
  { provider: 'otx',            env: 'OTX_API_KEY',              field: 'apiKey' },
  { provider: 'pulsedive',      env: 'PULSEDIVE_API_KEY',        field: 'apiKey' },
  { provider: 'safebrowsing',   env: 'GOOGLE_SAFE_BROWSING_KEY', field: 'apiKey' },
  { provider: 'hibp',           env: 'HIBP_API_KEY',             field: 'apiKey' },
  { provider: 'hybridanalysis', env: 'HYBRID_ANALYSIS_KEY',      field: 'apiKey' },
  { provider: 'threatfox',      env: 'THREATFOX_API_KEY',        field: 'apiKey' },
  { provider: 'urlhaus',        env: 'URLHAUS_API_KEY',          field: 'apiKey' },
  { provider: 'hunter',         env: 'HUNTER_API_KEY',           field: 'apiKey' },
  { provider: 'dnsdumpster',    env: 'DNSDUMPSTER_API_KEY',      field: 'apiKey' },
  { provider: 'ipapi',          env: 'IPAPI_KEY',                field: 'apiKey' },
] as const;

type ProviderKey = (typeof PROVIDER_KEYS)[number];
export type ProviderKeyEnv = ProviderKey['env'];

type ProviderConfig = {
  [P in ProviderKey as P['provider']]: { [F in P['field']]: string };
};

export interface Config extends ProviderConfig {
  port: number;
  cacheTtlMinutes: number;
  enableUrlSubmission: boolean;
  enableHighRiskEnrichment: boolean;
  logLevel: string;
  configuredProviders: string[];
}

function readProviderConfig(): ProviderConfig {
  const out: Record<string, Record<string, string>> = {};
  for (const { provider, env, field } of PROVIDER_KEYS) {
    out[provider] = { [field]: envStr(env) };
  }
  return out as ProviderConfig;
}

function listConfigured(): string[] {
  return PROVIDER_KEYS.filter(p => envStr(p.env)).map(p => p.provider);
}

export const config: Config = {
  ...readProviderConfig(),
  port: envInt('PORT', 8787),
  cacheTtlMinutes: envInt('CACHE_TTL_MINUTES', 60),
  enableUrlSubmission: envBool('ENABLE_URL_SUBMISSION', false),
  enableHighRiskEnrichment: envBool('ENABLE_HIGH_RISK_ENRICHMENT', false),
  logLevel: envStr('LOG_LEVEL', 'info'),
  configuredProviders: listConfigured(),
};

/**
 * Re-derives provider credentials from process.env in place.
 * Call this after writing new API keys so enrichment picks them up without a restart.
 */
export function reloadConfig(): void {
  Object.assign(config, readProviderConfig());
  config.configuredProviders.splice(0, config.configuredProviders.length, ...listConfigured());
}
