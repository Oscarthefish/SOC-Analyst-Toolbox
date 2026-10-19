import type { IocInput, EnrichmentResult, EnrichOptions, Severity } from '../types.js';
import { config } from '../config.js';
import { computeFreshness } from '../lib/freshness.js';
import { resultFactory } from '../lib/result.js';

const PROVIDER_ID = 'threatfox';
const PROVIDER_NAME = 'ThreatFox';
const TIMEOUT_MS = 10_000;
const API_URL = 'https://threatfox-api.abuse.ch/api/v1/';
const makeResult = resultFactory(PROVIDER_ID, PROVIDER_NAME);

interface ThreatFoxRecord {
  id?: string;
  ioc?: string;
  threat_type?: string;
  threat_type_desc?: string;
  ioc_type?: string;
  malware?: string;
  malware_printable?: string;
  confidence_level?: number;
  first_seen?: string;
  last_seen?: string;
  reporter?: string;
  tags?: string[] | null;
}

interface ThreatFoxResponse {
  query_status: string;
  data?: ThreatFoxRecord[] | null;
}

export async function threatfox(ioc: IocInput, _options: EnrichOptions): Promise<EnrichmentResult> {
  const apiKey = config.threatfox.apiKey;
  if (!apiKey) {
    return makeResult({ status: 'missing_key', summary: 'ThreatFox API key is not configured. Register free at threatfox.abuse.ch.' });
  }

  const supported = ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256'];
  if (!supported.includes(ioc.type)) {
    return makeResult({ status: 'unsupported_ioc', summary: `ThreatFox does not support IOC type: ${ioc.type}.` });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Auth-Key': apiKey, 'User-Agent': 'SOC-Analyst-Toolbox/1.0' },
      body: JSON.stringify({ query: 'search_ioc', search_term: ioc.normalised }),
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!res.ok) {
      return makeResult({ status: 'error', summary: `ThreatFox returned HTTP ${res.status}.`, errorMessage: `HTTP ${res.status}` });
    }

    const json = (await res.json()) as ThreatFoxResponse;

    if (json.query_status === 'no_result' || !json.data?.length) {
      return makeResult({
        status: 'ok', summary: 'ThreatFox: IOC not found in threat intelligence database.',
        severity: 'unknown', confidence: 'medium', data: { found: false },
      });
    }

    const records = json.data;
    const maxConfidence = Math.max(...records.map(r => r.confidence_level ?? 0));
    const malwares = [...new Set(records.map(r => r.malware_printable).filter(Boolean))];
    const threatTypes = [...new Set(records.map(r => r.threat_type).filter(Boolean))];
    const tags = [...new Set(records.flatMap(r => r.tags ?? []))];
    const top = records[0];

    let severity: Severity;
    if (maxConfidence >= 75) severity = 'high';
    else if (maxConfidence >= 50) severity = 'medium';
    else severity = 'low';

    const summary = `ThreatFox: IOC found in ${records.length} threat record(s). Malware: ${malwares.join(', ') || 'unknown'}. Type: ${threatTypes.join(', ') || 'unknown'}. Confidence: ${maxConfidence}%.${tags.length ? ` Tags: ${tags.join(', ')}.` : ''}`;

    const firstSeenDate = top.first_seen ?? undefined;
    const lastSeenDate = top.last_seen ?? undefined;

    return makeResult({
      status: 'ok', summary, severity, confidence: maxConfidence >= 75 ? 'high' : 'medium',
      data: { recordCount: records.length, malwares, threatTypes, maxConfidence, firstSeen: top.first_seen, lastSeen: top.last_seen, tags },
      rawAvailable: true,
      sourceUrl: `https://threatfox.abuse.ch/browse.php?search=ioc:${encodeURIComponent(ioc.normalised)}`,
      firstSeenDate,
      lastSeenDate,
      freshnessLabel: computeFreshness(lastSeenDate),
      sourceReliability: 'authoritative',
      keyFacts: [
        { label: 'Records found', value: String(records.length) },
        ...(malwares.length ? [{ label: 'Malware families', value: malwares.join(', ') }] : []),
        ...(threatTypes.length ? [{ label: 'Threat types', value: threatTypes.join(', ') }] : []),
        { label: 'Max confidence', value: `${maxConfidence}%` },
        ...(firstSeenDate ? [{ label: 'First seen', value: firstSeenDate }] : []),
        ...(lastSeenDate ? [{ label: 'Last seen', value: lastSeenDate }] : []),
        ...(tags.length ? [{ label: 'Tags', value: tags.join(', ') }] : []),
      ],
    });
  } catch (err) {
    clearTimeout(timeout);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({ status: 'error', summary: isTimeout ? 'ThreatFox request timed out.' : 'ThreatFox request failed.', errorMessage: err instanceof Error ? err.message : String(err) });
  }
}
