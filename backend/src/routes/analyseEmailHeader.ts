import { Router } from 'express';
import type { Request, Response } from 'express';
import type {
  IocInput,
  EnrichmentResult,
  OverallAssessment,
  EnrichOptions,
} from '../types.js';
import { adapters } from '../adapters/index.js';
import { config } from '../config.js';
import * as cache from '../cache.js';
import { isRateLimited, recordRequest } from '../rateLimit.js';
import { resolveOllamaModel, ollamaGenerate } from '../lib/ollama.js';
import { parseEmailHeaders } from '../lib/emailHeaders.js';
import { computeOverallAssessment, detectVpnOrTor, EMAIL_ACTIONS } from '../lib/scoring.js';
import type { ParsedEmailHeaders } from '../lib/emailHeaders.js';

const router = Router();
const DEFAULT_OLLAMA_MODEL = 'qwen2.5';

// ── Enrichment helpers ───────────────────────────────────────────────────────

const IP_PROVIDERS   = ['greynoise', 'abuseipdb', 'ipapi', 'torproject', 'ipinfo'];
const DOM_PROVIDERS  = ['virustotal', 'urlscan', 'whois', 'safebrowsing'];

async function runAdapter(
  providerId: string,
  ioc: IocInput,
  options: EnrichOptions,
): Promise<EnrichmentResult> {
  const adapter = adapters[providerId];
  if (!adapter) {
    return {
      providerId, providerName: providerId, status: 'error',
      summary: `No adapter found for provider: ${providerId}.`,
      severity: 'unknown', confidence: 'unknown',
      data: {}, rawAvailable: false,
      checkedAt: new Date().toISOString(), fromCache: false,
      errorMessage: 'Adapter not found',
    };
  }

  const cacheKey = cache.buildCacheKey(providerId, ioc.type, ioc.normalised, false);
  if (!options.forceRefresh) {
    const cached = cache.get(cacheKey);
    if (cached) return cached;
  }

  if (isRateLimited(providerId)) {
    return {
      providerId, providerName: providerId, status: 'rate_limited',
      summary: `${providerId} is currently rate-limited.`,
      severity: 'unknown', confidence: 'unknown',
      data: {}, rawAvailable: false,
      checkedAt: new Date().toISOString(), fromCache: false,
    };
  }

  try {
    recordRequest(providerId);
    const result = await adapter(ioc, options);
    if (result.status === 'ok' || result.status === 'missing_key') {
      cache.set(cacheKey, result, config.cacheTtlMinutes);
    }
    return result;
  } catch (err) {
    return {
      providerId, providerName: providerId, status: 'error',
      summary: `Unexpected error from ${providerId} adapter.`,
      severity: 'unknown', confidence: 'unknown',
      data: {}, rawAvailable: false,
      checkedAt: new Date().toISOString(), fromCache: false,
      errorMessage: err instanceof Error ? err.message : String(err),
    };
  }
}


// ── Ollama prompt ────────────────────────────────────────────────────────────

function buildEmailPrompt(
  parsed: ParsedEmailHeaders,
  ipResults: EnrichmentResult[],
  domResults: EnrichmentResult[],
  overall: OverallAssessment,
): string {
  const authStatus = [
    `SPF:   ${parsed.spf ?? 'not present'}`,
    `DKIM:  ${parsed.dkim ?? 'not present'}`,
    `DMARC: ${parsed.dmarc ?? 'not present'}${parsed.dmarcPolicy ? ` (policy=${parsed.dmarcPolicy})` : ''}`,
  ].join('\n');

  const suspicious = parsed.suspiciousIndicators.length > 0
    ? parsed.suspiciousIndicators.map(s => `  ⚠ ${s}`).join('\n')
    : '  None detected';

  const ipLines = ipResults.map(r => {
    const note = r.status !== 'ok' && r.status !== 'cached' ? ` [${r.status}]` : '';
    return `  - ${r.providerName}${note}: ${r.summary} (${r.severity})`;
  }).join('\n') || '  No IP enrichment data.';

  const domLines = domResults.map(r => {
    const note = r.status !== 'ok' && r.status !== 'cached' ? ` [${r.status}]` : '';
    return `  - ${r.providerName}${note}: ${r.summary} (${r.severity})`;
  }).join('\n') || '  No domain enrichment data.';

  const successCount = [...ipResults, ...domResults].filter(r => r.status === 'ok' || r.status === 'cached').length;
  const totalCount = ipResults.length + domResults.length;

  return `You are a SOC Tier 2 email security analyst. Analyze the email header intelligence below and write a concise triage report. Focus on phishing, spoofing, and authentication failures. Use analyst-level language. Synthesize — do not repeat data verbatim.

Respond in EXACTLY this format. No extra text, no markdown, no numbered lists:

VERDICT: [exactly one of: Benign / Low Risk / Suspicious / Likely Malicious / Malicious / Insufficient Data]

KEY FINDINGS:
- [finding]
- [finding]
- [finding]

RECOMMENDED ACTIONS:
- [SOC action]
- [SOC action]

ANALYST NOTES:
[2-3 sentences on confidence, data gaps, or notable context. No bullet points.]

---

EMAIL HEADER SUMMARY:
From:         ${parsed.fromAddress ?? 'unknown'}
To:           ${parsed.toAddress ?? 'unknown'}
Return-Path:  ${parsed.returnPathDomain ? `<...@${parsed.returnPathDomain}>` : 'unknown'}
Reply-To:     ${parsed.replyToDomain ? `<...@${parsed.replyToDomain}>` : 'not set'}
DKIM domain:  ${parsed.dkimDomain ?? 'not signed'}
Sending IP:   ${parsed.sendingIp ?? 'not extracted'}
Subject:      ${parsed.subject ?? '(not present)'}
Date:         ${parsed.date ?? '(not present)'}
Spam Score:   ${parsed.spamScore ?? 'not present'}

EMAIL AUTHENTICATION:
${authStatus}

SUSPICIOUS INDICATORS:
${suspicious}

SENDING IP ENRICHMENT (${parsed.sendingIp ?? 'none'}):
${ipLines}

FROM DOMAIN ENRICHMENT (${parsed.fromDomain ?? 'none'}):
${domLines}

Providers queried: ${totalCount} (${successCount} returned data)
Aggregated severity: ${overall.severity} | Confidence: ${overall.confidence}`;
}

// ── Route ────────────────────────────────────────────────────────────────────

router.post('/analyse-email-header', async (req: Request, res: Response): Promise<void> => {
  const body = req.body as {
    rawHeaders?: string;
    options?: { ollamaModel?: string; forceRefresh?: boolean };
  };

  if (!body.rawHeaders || typeof body.rawHeaders !== 'string' || body.rawHeaders.trim().length < 10) {
    res.status(400).json({ error: 'rawHeaders is required and must be a non-empty string.' });
    return;
  }

  const parsed = parseEmailHeaders(body.rawHeaders);
  const ollamaModel = body.options?.ollamaModel ?? DEFAULT_OLLAMA_MODEL;
  const forceRefresh = body.options?.forceRefresh ?? false;

  const enrichOptions: EnrichOptions = {
    forceRefresh,
    allowSensitiveUrl: false,
    allowUrlSubmission: false,
    includeRaw: false,
    includeHunter: false,
  };

  // Build IOC inputs for enrichment
  const ipIoc: IocInput | null = parsed.sendingIp
    ? { original: parsed.sendingIp, normalised: parsed.sendingIp, type: 'ipv4' }
    : null;

  const domIoc: IocInput | null = parsed.fromDomain
    ? { original: parsed.fromDomain, normalised: parsed.fromDomain, type: 'domain' }
    : null;

  // Run enrichment + Ollama resolution in parallel
  const ipTasks  = ipIoc  ? IP_PROVIDERS.map(p => runAdapter(p, ipIoc, enrichOptions))   : [];
  const domTasks = domIoc ? DOM_PROVIDERS.map(p => runAdapter(p, domIoc, enrichOptions)) : [];

  const [resolvedModelResult, ...enrichSettled] = await Promise.allSettled([
    resolveOllamaModel(ollamaModel),
    ...ipTasks,
    ...domTasks,
  ]);

  const allResults: EnrichmentResult[] = enrichSettled.map((s, i) => {
    const providerId = i < ipTasks.length
      ? (IP_PROVIDERS[i] ?? 'unknown')
      : (DOM_PROVIDERS[i - ipTasks.length] ?? 'unknown');
    if (s.status === 'fulfilled') return s.value;
    return {
      providerId, providerName: providerId, status: 'error' as const,
      summary: 'Provider threw an unexpected error.',
      severity: 'unknown' as const, confidence: 'unknown' as const,
      data: {}, rawAvailable: false,
      checkedAt: new Date().toISOString(), fromCache: false,
      errorMessage: s.reason instanceof Error ? s.reason.message : String(s.reason),
    };
  });

  const ipResults  = allResults.slice(0, ipTasks.length);
  const domResults = allResults.slice(ipTasks.length);

  const resolvedModel: string | null =
    resolvedModelResult.status === 'fulfilled' ? resolvedModelResult.value : null;

  // VPN/Tor flags come from the sending IP's providers only
  const overall = computeOverallAssessment(allResults, detectVpnOrTor(ipResults), EMAIL_ACTIONS);

  let narrative: string | null = null;
  let narrativeError: string | undefined;

  if (resolvedModel) {
    const prompt = buildEmailPrompt(parsed, ipResults, domResults, overall);
    try {
      narrative = await ollamaGenerate(resolvedModel, prompt);
    } catch (err) {
      const isTimeout = err instanceof Error && err.name === 'AbortError';
      narrativeError = isTimeout
        ? 'Ollama timed out. Try again or use a faster model.'
        : err instanceof Error ? err.message : 'Unknown Ollama error.';
    }
  } else {
    narrativeError = 'Ollama is not running or the model is not available.';
  }

  res.json({
    parsed,
    ipIoc,
    domIoc,
    results: allResults,
    ipResults,
    domResults,
    overall,
    narrative,
    narrativeError,
    ollamaModel: resolvedModel ?? ollamaModel,
    ollamaAvailable: resolvedModel !== null,
    analysedAt: new Date().toISOString(),
  });
});

export default router;
