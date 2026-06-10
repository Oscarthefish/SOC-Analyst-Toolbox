import fetch from 'node-fetch';
import type { IocInput, EnrichmentResult, EnrichOptions, Severity } from '../types.js';
import { config } from '../config.js';
import { markRateLimited } from '../rateLimit.js';

const PROVIDER_ID = 'hybridanalysis';
const PROVIDER_NAME = 'Hybrid Analysis';
const TIMEOUT_MS = 15_000;

function now(): string { return new Date().toISOString(); }

function makeResult(overrides: Partial<EnrichmentResult>): EnrichmentResult {
  return {
    providerId: PROVIDER_ID, providerName: PROVIDER_NAME,
    status: 'ok', summary: '', severity: 'unknown', confidence: 'unknown',
    data: {}, rawAvailable: false, checkedAt: now(), fromCache: false,
    ...overrides,
  };
}

interface HaResult {
  verdict?: string;
  threat_score?: number;
  threat_level?: number;
  type?: string;
  sha256?: string;
  md5?: string;
  sha1?: string;
  file_type?: string;
  vx_family?: string;
  av_detect?: number;
  submit_name?: string;
  environment_description?: string;
  analysis_start_time?: string;
}

function verdictToSeverity(verdict: string | undefined, score: number): Severity {
  switch (verdict?.toLowerCase()) {
    case 'malicious': return score >= 75 ? 'high' : 'medium';
    case 'suspicious': return 'medium';
    case 'no specific threat': return 'low';
    case 'whitelisted': return 'benign';
    default: return 'unknown';
  }
}

export async function hybridanalysis(ioc: IocInput, _options: EnrichOptions): Promise<EnrichmentResult> {
  const apiKey = config.hybridanalysis.apiKey;
  if (!apiKey) {
    return makeResult({ status: 'missing_key', summary: 'Hybrid Analysis API key is not configured.' });
  }

  const supported = ['md5', 'sha1', 'sha256'];
  if (!supported.includes(ioc.type)) {
    return makeResult({ status: 'unsupported_ioc', summary: `Hybrid Analysis hash search only supports MD5/SHA1/SHA256 (got: ${ioc.type}).` });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const body = new URLSearchParams({ hash: ioc.normalised });
    const res = await fetch('https://www.hybrid-analysis.com/api/v2/search/hash', {
      method: 'POST',
      headers: {
        'api-key': apiKey,
        'User-Agent': 'Falcon Sandbox',
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: body.toString(),
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (res.status === 429) {
      markRateLimited(PROVIDER_ID);
      return makeResult({ status: 'rate_limited', summary: 'Hybrid Analysis rate limit reached. Try again later.' });
    }
    if (res.status === 401 || res.status === 403) {
      return makeResult({ status: 'error', summary: 'Hybrid Analysis: Invalid API key.', errorMessage: `HTTP ${res.status}` });
    }
    if (!res.ok) {
      return makeResult({ status: 'error', summary: `Hybrid Analysis returned HTTP ${res.status}.`, errorMessage: `HTTP ${res.status}` });
    }

    const results = (await res.json()) as HaResult[];

    if (!results?.length) {
      return makeResult({
        status: 'ok', summary: 'Hybrid Analysis: No sandbox reports found for this hash.',
        severity: 'unknown', confidence: 'medium', data: { found: false },
        sourceUrl: `https://www.hybrid-analysis.com/sample/${ioc.normalised}`,
      });
    }

    // Pick highest threat score result
    const top = results.reduce((a, b) => (b.threat_score ?? 0) > (a.threat_score ?? 0) ? b : a, results[0]);
    const verdict = top.verdict ?? 'unknown';
    const score = top.threat_score ?? 0;
    const severity = verdictToSeverity(verdict, score);
    const family = top.vx_family ?? '';
    const avDetect = top.av_detect ?? 0;
    const fileType = top.file_type ?? 'unknown';

    let summary = `Hybrid Analysis: ${verdict.toUpperCase()} (threat score: ${score}/100, ${results.length} report(s)).`;
    if (family) summary += ` Family: ${family}.`;
    if (avDetect) summary += ` AV detections: ${avDetect}.`;
    summary += ` File type: ${fileType}.`;

    return makeResult({
      status: 'ok', summary, severity, confidence: results.length > 0 ? 'high' : 'medium',
      data: { verdict, threatScore: score, reportCount: results.length, family, avDetect, fileType, sha256: top.sha256, md5: top.md5 },
      rawAvailable: true,
      sourceUrl: `https://www.hybrid-analysis.com/sample/${top.sha256 ?? ioc.normalised}`,
      sourceReliability: 'commercial-ti' as const,
      keyFacts: [
        { label: 'Verdict', value: verdict.toUpperCase() },
        { label: 'Threat score', value: `${score}/100` },
        { label: 'Reports', value: String(results.length) },
        ...(family ? [{ label: 'Family', value: family }] : []),
        ...(avDetect ? [{ label: 'AV detections', value: String(avDetect) }] : []),
        { label: 'File type', value: fileType },
      ],
    });
  } catch (err) {
    clearTimeout(timeout);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({ status: 'error', summary: isTimeout ? 'Hybrid Analysis request timed out.' : 'Hybrid Analysis request failed.', errorMessage: err instanceof Error ? err.message : String(err) });
  }
}
