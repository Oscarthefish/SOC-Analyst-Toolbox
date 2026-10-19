import type { IocInput, EnrichmentResult, EnrichOptions, Severity } from '../types.js';
import { config } from '../config.js';
import { resultFactory } from '../lib/result.js';

const PROVIDER_ID = 'urlhaus';
const PROVIDER_NAME = 'URLhaus';
const TIMEOUT_MS = 10_000;
const makeResult = resultFactory(PROVIDER_ID, PROVIDER_NAME);

interface UrlhausUrlResponse {
  query_status: string;
  id?: string;
  url_status?: string;
  threat?: string;
  tags?: string[] | null;
  urlhaus_reference?: string;
  blacklists?: Record<string, string>;
}

interface UrlhausHostResponse {
  query_status: string;
  urlhaus_reference?: string;
  url_count?: number;
  blacklists?: Record<string, string>;
  urls?: Array<{ url_status?: string; threat?: string }>;
}

export async function urlhaus(ioc: IocInput, _options: EnrichOptions): Promise<EnrichmentResult> {
  const apiKey = config.urlhaus.apiKey;
  if (!apiKey) {
    return makeResult({ status: 'missing_key', summary: 'URLhaus API key is not configured. Register free at abuse.ch/.' });
  }

  const supported = ['url', 'domain', 'ipv4'];
  if (!supported.includes(ioc.type)) {
    return makeResult({ status: 'unsupported_ioc', summary: `URLhaus does not support IOC type: ${ioc.type}.` });
  }

  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Auth-Key': apiKey,
  };

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    let res;
    if (ioc.type === 'url') {
      res = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
        method: 'POST',
        headers,
        body: new URLSearchParams({ url: ioc.normalised }).toString(),
        signal: controller.signal,
      });
    } else {
      res = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
        method: 'POST',
        headers,
        body: new URLSearchParams({ host: ioc.normalised }).toString(),
        signal: controller.signal,
      });
    }
    clearTimeout(timeout);

    if (!res.ok) {
      return makeResult({ status: 'error', summary: `URLhaus returned HTTP ${res.status}.`, errorMessage: `HTTP ${res.status}` });
    }

    if (ioc.type === 'url') {
      const json = (await res.json()) as UrlhausUrlResponse;

      if (json.query_status === 'unknown_auth_key') {
        return makeResult({ status: 'error', summary: 'URLhaus: Invalid API key.', errorMessage: 'unknown_auth_key' });
      }

      if (json.query_status === 'no_results' || json.query_status === 'is_available') {
        return makeResult({
          status: 'ok', summary: 'URLhaus: URL not found in malicious URL database.',
          severity: 'unknown', confidence: 'medium', data: { found: false },
        });
      }

      const urlStatus = json.url_status ?? 'unknown';
      const threat = json.threat ?? 'unknown';
      const tags = json.tags ?? [];
      const listedBlacklists = Object.entries(json.blacklists ?? {})
        .filter(([, v]) => v !== 'not listed').map(([k]) => k);

      const severity: Severity = urlStatus === 'online' ? 'high' : 'medium';
      const summary = `URLhaus: ${urlStatus === 'online' ? 'ACTIVE MALICIOUS URL' : 'Known malicious URL (offline)'} — threat: ${threat}.${tags.length ? ` Tags: ${tags.join(', ')}.` : ''}${listedBlacklists.length ? ` Blacklisted: ${listedBlacklists.join(', ')}.` : ''}`;

      return makeResult({
        status: 'ok', summary, severity, confidence: 'high',
        data: { urlStatus, threat, tags, blacklists: listedBlacklists },
        rawAvailable: true, sourceUrl: json.urlhaus_reference,
        sourceReliability: 'community' as const,
        keyFacts: [
          { label: 'URL status', value: urlStatus === 'online' ? 'ACTIVE (online)' : urlStatus },
          { label: 'Threat', value: threat },
          ...(tags.length > 0 ? [{ label: 'Tags', value: tags.join(', ') }] : []),
          ...(listedBlacklists.length > 0 ? [{ label: 'Blacklisted', value: listedBlacklists.join(', ') }] : []),
        ],
      });
    } else {
      const json = (await res.json()) as UrlhausHostResponse;

      if (json.query_status === 'unknown_auth_key') {
        return makeResult({ status: 'error', summary: 'URLhaus: Invalid API key.', errorMessage: 'unknown_auth_key' });
      }

      if (json.query_status === 'no_results') {
        return makeResult({
          status: 'ok', summary: 'URLhaus: Host not found in malicious URL database.',
          severity: 'unknown', confidence: 'medium', data: { found: false },
        });
      }

      const urlCount = json.url_count ?? 0;
      const activeUrls = json.urls?.filter(u => u.url_status === 'online').length ?? 0;
      const threats = [...new Set(json.urls?.map(u => u.threat).filter(Boolean) ?? [])];
      const listedBlacklists = Object.entries(json.blacklists ?? {})
        .filter(([, v]) => v !== 'not listed').map(([k]) => k);

      const severity: Severity = activeUrls > 0 ? 'high' : urlCount > 0 ? 'medium' : 'unknown';
      const summary = `URLhaus: ${urlCount} malicious URL(s) associated with this host (${activeUrls} active).${threats.length ? ` Threats: ${threats.join(', ')}.` : ''}${listedBlacklists.length ? ` Blacklisted: ${listedBlacklists.join(', ')}.` : ''}`;

      return makeResult({
        status: 'ok', summary, severity, confidence: urlCount > 0 ? 'high' : 'medium',
        data: { urlCount, activeUrls, threats, blacklists: listedBlacklists },
        rawAvailable: true, sourceUrl: json.urlhaus_reference,
        sourceReliability: 'community' as const,
        keyFacts: [
          { label: 'Malicious URLs', value: `${urlCount} (${activeUrls} active)` },
          ...(threats.length > 0 ? [{ label: 'Threats', value: threats.join(', ') }] : []),
          ...(listedBlacklists.length > 0 ? [{ label: 'Blacklisted', value: listedBlacklists.join(', ') }] : []),
        ],
      });
    }
  } catch (err) {
    clearTimeout(timeout);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({ status: 'error', summary: isTimeout ? 'URLhaus request timed out.' : 'URLhaus request failed.', errorMessage: err instanceof Error ? err.message : String(err) });
  }
}
