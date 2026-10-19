import type { IocInput, EnrichmentResult, EnrichOptions, Severity } from '../types.js';
import { config } from '../config.js';
import { markRateLimited } from '../rateLimit.js';
import { computeFreshness } from '../lib/freshness.js';
import { resultFactory } from '../lib/result.js';

const PROVIDER_ID = 'greynoise';
const PROVIDER_NAME = 'GreyNoise';
const TIMEOUT_MS = 10_000;
const makeResult = resultFactory(PROVIDER_ID, PROVIDER_NAME);

interface GreyNoiseCommunityResponse {
  ip?: string;
  noise?: boolean;
  riot?: boolean;
  classification?: string;
  name?: string;
  link?: string;
  last_seen?: string;
  message?: string;
}

export async function greynoise(
  ioc: IocInput,
  _options: EnrichOptions,
): Promise<EnrichmentResult> {
  if (ioc.type !== 'ipv4' && ioc.type !== 'ipv6') {
    return makeResult({
      status: 'unsupported_ioc',
      summary: `GreyNoise does not support IOC type: ${ioc.type}.`,
      severity: 'unknown',
      confidence: 'unknown',
    });
  }

  const apiKey = config.greynoise.apiKey;

  const url = `https://api.greynoise.io/v3/community/${encodeURIComponent(ioc.normalised)}`;
  const headers: Record<string, string> = {};
  if (apiKey) headers['key'] = apiKey;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      headers,
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (res.status === 429) {
      markRateLimited(PROVIDER_ID);
      return makeResult({
        status: 'rate_limited',
        summary: 'GreyNoise rate limit reached. Try again in 60 seconds.',
        severity: 'unknown',
        confidence: 'unknown',
      });
    }

    if (res.status === 404) {
      // GreyNoise returns a JSON body even on 404 with noise/riot/message fields
      let notFoundMessage = 'GreyNoise has no context for this IP — not observed in noise or RIOT dataset.';
      try {
        const body404 = (await res.json()) as GreyNoiseCommunityResponse;
        if (body404.message) notFoundMessage = `GreyNoise: ${body404.message}`;
      } catch { /* ignore parse errors */ }
      return makeResult({
        status: 'ok',
        summary: notFoundMessage,
        severity: 'unknown',
        confidence: 'low',
        data: { ip: ioc.normalised, inDataset: false },
      });
    }

    if (res.status === 400) {
      return makeResult({
        status: 'unsupported_ioc',
        summary: 'GreyNoise: invalid or non-routable IP address (private/reserved ranges are not supported).',
        severity: 'unknown',
        confidence: 'unknown',
      });
    }

    if (res.status === 401 || res.status === 403) {
      return makeResult({
        status: 'error',
        summary: 'GreyNoise: API key is invalid or unauthorised.',
        severity: 'unknown',
        confidence: 'unknown',
        errorMessage: `HTTP ${res.status} — check your GREYNOISE_API_KEY in backend/.env`,
      });
    }

    if (!res.ok) {
      return makeResult({
        status: 'error',
        summary: `GreyNoise returned HTTP ${res.status}.`,
        severity: 'unknown',
        confidence: 'unknown',
        errorMessage: `HTTP ${res.status}`,
      });
    }

    const body = (await res.json()) as GreyNoiseCommunityResponse;
    const classification = body.classification ?? '';
    const noise = body.noise ?? false;
    const riot = body.riot ?? false;
    const name = body.name ?? '';
    const lastSeen = body.last_seen ?? '';
    // Use the link field from the API response — GreyNoise provides the correct viz URL
    const vizUrl = body.link ?? `https://viz.greynoise.io/riot/${ioc.normalised}`;

    let severity: Severity = 'unknown';
    let summary = '';

    if (classification === 'malicious') {
      severity = 'high';
      summary = `GreyNoise classifies this IP as MALICIOUS${name ? ` (${name})` : ''}. Last seen: ${lastSeen || 'unknown'}.`;
    } else if (classification === 'benign' || riot) {
      severity = 'benign';
      summary = riot
        ? `GreyNoise identifies this IP as a benign RIOT (known-good internet service)${name ? `: ${name}` : ''}.`
        : `GreyNoise classifies this IP as benign${name ? ` (${name})` : ''}. Last seen: ${lastSeen || 'unknown'}.`;
    } else if (noise && classification === '') {
      severity = 'low';
      summary = `GreyNoise sees this IP as internet background noise (unclassified). Last seen: ${lastSeen || 'unknown'}.`;
    } else if (classification) {
      severity = 'low';
      summary = `GreyNoise classification: ${classification}${name ? ` (${name})` : ''}. Last seen: ${lastSeen || 'unknown'}.`;
    } else {
      severity = 'unknown';
      summary = 'GreyNoise returned data but classification is unclear.';
    }

    const lastSeenDate = lastSeen ? new Date(lastSeen).toISOString() : undefined;

    return makeResult({
      status: 'ok',
      summary,
      severity,
      confidence: 'high',
      data: {
        ip: body.ip,
        classification,
        noise,
        riot,
        name,
        lastSeen,
      },
      rawAvailable: true,
      sourceUrl: vizUrl,
      lastSeenDate,
      freshnessLabel: computeFreshness(lastSeenDate),
      sourceReliability: 'commercial-ti',
      keyFacts: [
        { label: 'Classification', value: classification || (riot ? 'RIOT (benign)' : 'unknown') },
        ...(name ? [{ label: 'Name', value: name }] : []),
        ...(noise ? [{ label: 'Internet noise', value: 'yes' }] : []),
        ...(riot ? [{ label: 'RIOT', value: 'yes — known good service' }] : []),
        ...(lastSeen ? [{ label: 'Last seen', value: lastSeen }] : []),
      ],
    });
  } catch (err) {
    clearTimeout(timeout);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({
      status: 'error',
      summary: isTimeout ? 'GreyNoise request timed out.' : 'GreyNoise request failed.',
      severity: 'unknown',
      confidence: 'unknown',
      errorMessage: err instanceof Error ? err.message : String(err),
    });
  }
}
