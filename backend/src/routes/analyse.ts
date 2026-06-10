import { Router } from 'express';
import type { Request, Response } from 'express';
import type {
  IocInput,
  IocType,
  EnrichmentResult,
  EnrichmentResponse,
  OverallAssessment,
  EnrichOptions,
  Severity,
  Confidence,
  ContradictionFlag,
} from '../types.js';
import { adapters } from '../adapters/index.js';
import { config } from '../config.js';
import * as cache from '../cache.js';
import { isRateLimited, recordRequest } from '../rateLimit.js';
import { resolveOllamaModel, ollamaGenerate } from '../lib/ollama.js';
import { getProviderTtl } from '../lib/providerTtl.js';

const router = Router();
const DEFAULT_OLLAMA_MODEL = 'qwen2.5';

const VALID_IOC_TYPES: IocType[] = [
  'ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email', 'asn', 'cidr', 'cve',
];

const ANALYSE_PROVIDERS: Record<string, string[]> = {
  ipv4:   ['greynoise', 'abuseipdb', 'ipapi', 'torproject', 'ipinfo', 'virustotal', 'shodan', 'censys', 'whois', 'otx', 'pulsedive', 'threatfox', 'bgpview'],
  ipv6:   ['greynoise', 'abuseipdb', 'ipapi', 'torproject', 'ipinfo', 'virustotal', 'censys', 'whois', 'otx', 'pulsedive', 'threatfox', 'bgpview'],
  domain: ['dns', 'crtsh', 'wayback', 'virustotal', 'urlscan', 'whois', 'otx', 'pulsedive', 'threatfox', 'urlhaus', 'safebrowsing', 'ransomwarelive'],
  url:    ['urlscan', 'virustotal', 'otx', 'pulsedive', 'threatfox', 'urlhaus', 'safebrowsing', 'ransomwarelive'],
  md5:    ['virustotal', 'malwarebazaar', 'threatfox', 'otx', 'hybridanalysis'],
  sha1:   ['virustotal', 'malwarebazaar', 'threatfox', 'otx', 'hybridanalysis'],
  sha256: ['virustotal', 'malwarebazaar', 'threatfox', 'otx', 'hybridanalysis'],
  email:  ['hibp'],
  asn:    ['bgpview'],
  cidr:   ['bgpview'],
  cve:    ['cisakev'],
};

// Passive/contextual sources that should not contribute to severity scoring
const PASSIVE_PROVIDERS = new Set(['bgpview', 'ipapi', 'ipinfo', 'torproject', 'whois', 'dns', 'crtsh', 'wayback', 'hunter']);

function detectContradictions(results: EnrichmentResult[]): ContradictionFlag[] {
  const flags: ContradictionFlag[] = [];
  const successful = results.filter(r => r.status === 'ok' || r.status === 'cached');

  const activeSources = successful.filter(r => !PASSIVE_PROVIDERS.has(r.providerId));
  const highSeverity = activeSources.filter(r => r.severity === 'high' || r.severity === 'critical');
  const benignResults = activeSources.filter(r => r.severity === 'benign');

  // Contradiction: some sources say benign, others say malicious/high
  if (highSeverity.length > 0 && benignResults.length > 0) {
    flags.push({
      type: 'CONFLICT_BENIGN_VS_MALICIOUS',
      message: `${benignResults.map(r => r.providerName).join(', ')} classify as benign/clean, but ${highSeverity.map(r => r.providerName).join(', ')} flag as high severity or malicious.`,
      sources: [...highSeverity, ...benignResults].map(r => r.providerId),
      recommendation: 'Investigate whether this is shared infrastructure (CDN, hosting provider, VPN exit) where platform reputation does not reflect specific hosted content.',
    });
  }

  // Low-count VT detection with no corroboration
  const vtResult = successful.find(r => r.providerId === 'virustotal');
  if (vtResult && (vtResult.status === 'ok' || vtResult.status === 'cached')) {
    const malicious = vtResult.data.malicious as number | undefined;
    const harmless = vtResult.data.harmless as number | undefined;
    const undetected = vtResult.data.undetected as number | undefined;
    const suspicious = vtResult.data.suspicious as number | undefined;
    const total = (malicious ?? 0) + (harmless ?? 0) + (undetected ?? 0) + (suspicious ?? 0);
    if (malicious && malicious <= 2 && total > 10) {
      const otherHighResults = highSeverity.filter(r => r.providerId !== 'virustotal');
      if (otherHighResults.length === 0) {
        flags.push({
          type: 'LOW_DETECTION_NO_CORROBORATION',
          message: `VirusTotal shows only ${malicious}/${total} engine detections with no corroboration from other sources.`,
          sources: ['virustotal'],
          recommendation: 'Low-count VT detections without corroboration are often false positives. Consider sandbox analysis or additional context before acting.',
        });
      }
    }
  }

  // Newly registered domain with no detections
  const whoisResult = successful.find(r => r.providerId === 'whois');
  if (whoisResult && (whoisResult.status === 'ok' || whoisResult.status === 'cached')) {
    const age = whoisResult.data.domainAge;
    if (typeof age === 'number' && age >= 0 && age <= 14) {
      const anyThreat = activeSources.some(r =>
        r.severity === 'high' || r.severity === 'critical' || r.severity === 'medium');
      if (!anyThreat) {
        flags.push({
          type: 'NEWLY_REGISTERED_UNDETECTED',
          message: `Domain is only ${age} day(s) old but has no detections from checked sources.`,
          sources: ['whois'],
          recommendation: 'Newly registered domains with no detections are not confirmed benign. Absence of detection is not proof of safety for new domains — monitor closely.',
        });
      }
    }

    // DOMAIN_AGE_ARCHIVE_MISMATCH: WHOIS says old domain but Wayback has no or very recent archive
    const waybackResult = successful.find(r => r.providerId === 'wayback');
    if (
      waybackResult && (waybackResult.status === 'ok' || waybackResult.status === 'cached') &&
      typeof age === 'number' && age > 365
    ) {
      const firstArchivedFact = waybackResult.keyFacts?.find(f => f.label === 'First archived');
      if (!firstArchivedFact) {
        flags.push({
          type: 'DOMAIN_AGE_ARCHIVE_MISMATCH',
          message: `WHOIS shows domain age of ${age} days, but Wayback Machine has no archived snapshots for this domain.`,
          sources: ['whois', 'wayback'],
          recommendation: 'This may indicate a recently re-registered or re-purposed domain. The domain may have dropped and been re-registered, or never had a web presence. Treat as higher risk.',
        });
      } else {
        // Check if first archive is much more recent than WHOIS registration
        const firstDate = new Date(firstArchivedFact.value.split(' ')[0] ?? firstArchivedFact.value);
        const archiveDaysAgo = Math.floor((Date.now() - firstDate.getTime()) / 86_400_000);
        if (!isNaN(archiveDaysAgo) && age > 365 && archiveDaysAgo < 90) {
          flags.push({
            type: 'DOMAIN_AGE_ARCHIVE_MISMATCH',
            message: `WHOIS shows domain age of ${age} days, but Wayback Machine first snapshot is only ${archiveDaysAgo} day(s) ago. The domain may have been re-registered or repurposed.`,
            sources: ['whois', 'wayback'],
            recommendation: 'Domain re-registration is a common technique to abuse the reputation of expired domains. Check historical WHOIS records and compare with current content.',
          });
        }
      }
    }
  }

  return flags;
}

function computeOverallAssessment(results: EnrichmentResult[]): OverallAssessment {
  const successful = results.filter(r => r.status === 'ok' || r.status === 'cached');
  // Only active (non-passive) sources contribute to severity
  const activeSources = successful.filter(r => !PASSIVE_PROVIDERS.has(r.providerId));

  const severityCounts: Record<Severity, number> = {
    critical: 0, high: 0, medium: 0, low: 0, benign: 0, unknown: 0,
  };
  for (const r of activeSources) {
    severityCounts[r.severity] = (severityCounts[r.severity] ?? 0) + 1;
  }

  let severity: Severity;
  const recommendedActions: string[] = [];

  if (severityCounts.critical > 0) {
    severity = 'critical';
    recommendedActions.push('Immediately isolate affected systems.');
    recommendedActions.push('Escalate to Tier 2/3 or incident response.');
    recommendedActions.push('Block IOC across all controls (firewall, proxy, EDR).');
    recommendedActions.push('Initiate incident response procedure.');
  } else if (severityCounts.high >= 2 || (severityCounts.high >= 1 && severityCounts.medium >= 1)) {
    severity = 'high';
    recommendedActions.push('Block IOC at firewall and proxy.');
    recommendedActions.push('Search for related IOCs across environment.');
    recommendedActions.push('Escalate to senior analyst for review.');
  } else if (severityCounts.high >= 1) {
    severity = 'high';
    recommendedActions.push('Block IOC at perimeter controls.');
    recommendedActions.push('Investigate correlated events in SIEM.');
  } else if (severityCounts.medium >= 1) {
    severity = 'medium';
    recommendedActions.push('Monitor for additional activity from this IOC.');
    recommendedActions.push('Consider adding to watchlist.');
  } else if (severityCounts.low > 0) {
    severity = 'low';
    recommendedActions.push('Log and monitor. No immediate action required.');
  } else if (severityCounts.benign > 0 && severityCounts.unknown === 0) {
    severity = 'benign';
    recommendedActions.push('No action required. Document findings.');
  } else {
    severity = 'unknown';
    recommendedActions.push('Insufficient data. Consider manual investigation.');
    recommendedActions.push('Check if additional API keys can be configured.');
  }

  // Confidence based on data quality: how many active sources returned data
  const activeDataCount = activeSources.length;
  const allHistorical = activeSources.every(r =>
    r.freshnessLabel === 'historical' || r.freshnessLabel === 'unknown');

  let confidence: Confidence;
  if (activeDataCount >= 3 && !allHistorical) {
    confidence = 'high';
  } else if (activeDataCount >= 1) {
    confidence = allHistorical ? 'low' : 'medium';
  } else {
    confidence = 'low';
  }

  const severityLabel = severity.charAt(0).toUpperCase() + severity.slice(1);
  const summary = successful.length === 0
    ? 'No enrichment providers returned data. Check API key configuration.'
    : `Aggregated assessment from ${successful.length} provider(s): ${severityLabel} severity, ${confidence} confidence.`;

  return { severity, confidence, summary, recommendedActions };
}

async function runAdapter(
  providerId: string,
  ioc: IocInput,
  options: EnrichOptions,
): Promise<EnrichmentResult> {
  const adapter = adapters[providerId];
  if (!adapter) {
    return {
      providerId,
      providerName: providerId,
      status: 'error',
      summary: `No adapter found for provider: ${providerId}.`,
      severity: 'unknown',
      confidence: 'unknown',
      data: {},
      rawAvailable: false,
      checkedAt: new Date().toISOString(),
      fromCache: false,
      errorMessage: 'Adapter not found',
    };
  }

  const isSensitiveUrl = ioc.type === 'url';
  const cacheKey = cache.buildCacheKey(providerId, ioc.type, ioc.normalised, isSensitiveUrl);

  if (!options.forceRefresh) {
    const cached = cache.get(cacheKey);
    if (cached) return cached;
  }

  if (isRateLimited(providerId)) {
    return {
      providerId,
      providerName: providerId,
      status: 'rate_limited',
      summary: `${providerId} is currently rate-limited. Try again later.`,
      severity: 'unknown',
      confidence: 'unknown',
      data: {},
      rawAvailable: false,
      checkedAt: new Date().toISOString(),
      fromCache: false,
    };
  }

  try {
    recordRequest(providerId);
    const result = await adapter(ioc, options);
    if (result.status === 'ok' || result.status === 'missing_key') {
      const ttl = getProviderTtl(providerId, config.cacheTtlMinutes);
      cache.set(cacheKey, result, ttl);
    }
    return result;
  } catch (err) {
    return {
      providerId,
      providerName: providerId,
      status: 'error',
      summary: `Unexpected error from ${providerId} adapter.`,
      severity: 'unknown',
      confidence: 'unknown',
      data: {},
      rawAvailable: false,
      checkedAt: new Date().toISOString(),
      fromCache: false,
      errorMessage: err instanceof Error ? err.message : String(err),
    };
  }
}

function buildAnalysisPrompt(
  ioc: IocInput,
  workflowId: string | undefined,
  results: EnrichmentResult[],
  overall: OverallAssessment,
  contradictions: ContradictionFlag[],
): string {
  const typeLabel = ioc.type.toUpperCase();
  const workflow = workflowId ? workflowId.replace(/-/g, ' ') : 'general investigation';

  const successful = results.filter(r => r.status === 'ok' || r.status === 'cached');
  const missingCount = results.filter(r => r.status === 'missing_key').length;

  // Build structured fact sheet from key facts
  const factSheet = successful.map(r => {
    const entry: Record<string, string | boolean | undefined> = {
      source: r.providerName,
      tier: r.sourceReliability ?? 'unknown',
      severity: r.severity,
      confidence: r.confidence,
      freshness: r.freshnessLabel ?? 'unknown',
      lastSeen: r.lastSeenDate ?? 'not provided',
    };
    if (r.keyFacts && r.keyFacts.length > 0) {
      for (const kf of r.keyFacts) {
        const key = kf.label.toLowerCase().replace(/\s+/g, '_');
        entry[key] = kf.timestamp ? `${kf.value} (as of ${kf.timestamp.split('T')[0]})` : kf.value;
      }
    }
    if (r.sourceUrl) entry.source_url = r.sourceUrl;
    return entry;
  });

  // WHOIS context for registration data
  const whoisResult = successful.find(r => r.providerId === 'whois');
  let whoisSection = 'No WHOIS/registration data available.';
  if (whoisResult) {
    const d = whoisResult.data;
    const parts: string[] = [];
    if (d.domainAge !== null && d.domainAge !== undefined) parts.push(`Domain age: ${String(d.domainAge)} days`);
    if (d.registrar) parts.push(`Registrar: ${String(d.registrar)}`);
    if (d.registrationDate) parts.push(`Registered: ${String(d.registrationDate).split('T')[0]}`);
    if (d.country) parts.push(`Country: ${String(d.country)}`);
    if (d.registrantOrg) parts.push(`Org: ${String(d.registrantOrg)}`);
    if (Array.isArray(d.nameservers) && d.nameservers.length > 0) {
      parts.push(`Nameservers: ${(d.nameservers as string[]).join(', ')}`);
    }
    whoisSection = parts.length > 0 ? parts.join(' | ') : whoisResult.summary;
  }

  const contradictionSection = contradictions.length > 0
    ? `CONTRADICTIONS DETECTED (${contradictions.length}):\n${contradictions.map(c =>
        `  [${c.type}] ${c.message}\n  → ${c.recommendation}`
      ).join('\n\n')}`
    : 'CONTRADICTIONS: None detected.';

  return `You are a SOC Tier-2 analyst reviewing structured threat intelligence data.
RULES — follow these exactly:
1. Every claim in KEY FINDINGS must name the source in [brackets], e.g. "[VirusTotal]".
2. Never use the words "safe", "clean", or "benign" unless a source explicitly classified the IOC as benign. Use "not detected by [source]" instead.
3. If this is an IP belonging to a CDN or major cloud provider (Cloudflare, Akamai, AWS, Azure, GCP, Fastly, Cloudfront), you MUST state this and clarify that reputation reflects the platform, not specific hosted content.
4. If all source data is historical (freshness = historical or unknown), state this in ANALYST NOTES.
5. If fewer than 2 active sources returned data, set confidence to Low regardless of severity.
6. You MUST address every contradiction listed in CONTRADICTIONS DETECTED.
7. Do not recommend blocking based solely on a single reputation source with no corroboration.

Respond in EXACTLY this format. No markdown, no extra text:

VERDICT: [exactly one of: Benign / Low Risk / Suspicious / Likely Malicious / Malicious / Insufficient Data]

KEY FINDINGS:
- [Source] finding
- [Source] finding
- [Source] finding

THREAT CONTEXT:
[Campaign name, malware family, ransomware group, or CVE if present. Write "None identified in checked sources." if absent.]

SOURCE CONFLICTS:
[Address any contradictions explicitly. Write "No conflicts detected." if absent.]

ANALYST NOTES:
[2-3 sentences covering: data freshness, confidence rationale, and any significant gaps. Be specific about what was not checked.]

RECOMMENDED ACTIONS:
- [SOC action]
- [SOC action]

---

IOC: ${ioc.normalised} (${typeLabel})
Investigation: ${workflow}
Sources queried: ${results.length} total, ${successful.length} returned data${missingCount > 0 ? `, ${missingCount} have no API key configured` : ''}
Aggregated severity: ${overall.severity} | Confidence: ${overall.confidence}

STRUCTURED SOURCE DATA:
${JSON.stringify(factSheet, null, 2)}

REGISTRATION / NETWORK CONTEXT:
${whoisSection}

${contradictionSection}`;
}

router.post('/analyse', async (req: Request, res: Response): Promise<void> => {
  const body = req.body as {
    ioc?: Partial<IocInput>;
    workflowId?: string;
    options?: { ollamaModel?: string; forceRefresh?: boolean; includeHunter?: boolean };
  };

  if (!body.ioc?.normalised || !body.ioc.type) {
    res.status(400).json({ error: 'ioc.normalised and ioc.type are required.' });
    return;
  }

  if (!VALID_IOC_TYPES.includes(body.ioc.type as IocType)) {
    res.status(400).json({ error: `Invalid IOC type: ${body.ioc.type}` });
    return;
  }

  const ioc: IocInput = {
    original: body.ioc.original ?? body.ioc.normalised,
    normalised: body.ioc.normalised,
    type: body.ioc.type as IocType,
  };

  const workflowId = body.workflowId;
  const ollamaModel = body.options?.ollamaModel ?? DEFAULT_OLLAMA_MODEL;
  const forceRefresh = body.options?.forceRefresh ?? false;
  const includeHunter = body.options?.includeHunter ?? false;

  const enrichOptions: EnrichOptions = {
    forceRefresh,
    allowSensitiveUrl: false,
    allowUrlSubmission: false,
    includeRaw: false,
    includeHunter,
  };

  let providerList = ANALYSE_PROVIDERS[ioc.type] ?? [];
  if (includeHunter && (ioc.type === 'domain' || ioc.type === 'url' || ioc.type === 'email') && !providerList.includes('hunter')) {
    providerList = [...providerList, 'hunter'];
  }

  const [resolvedModelResult, ...enrichSettled] = await Promise.allSettled([
    resolveOllamaModel(ollamaModel),
    ...providerList.map(p => runAdapter(p, ioc, enrichOptions)),
  ]);

  const results: EnrichmentResult[] = enrichSettled.map((s, i) => {
    if (s.status === 'fulfilled') return s.value;
    return {
      providerId: providerList[i] ?? 'unknown',
      providerName: providerList[i] ?? 'unknown',
      status: 'error' as const,
      summary: 'Provider threw an unexpected error.',
      severity: 'unknown' as const,
      confidence: 'unknown' as const,
      data: {},
      rawAvailable: false,
      checkedAt: new Date().toISOString(),
      fromCache: false,
      errorMessage: s.reason instanceof Error ? s.reason.message : String(s.reason),
    };
  });

  const resolvedModel: string | null =
    resolvedModelResult.status === 'fulfilled' ? resolvedModelResult.value : null;

  const contradictions = detectContradictions(results);
  const overall = computeOverallAssessment(results);

  let narrative: string | null = null;
  let narrativeError: string | undefined;
  let citationRetried = false;

  const successful = results.filter(r => r.status === 'ok' || r.status === 'cached');
  const sourceNames = successful.map(r => r.providerName);

  function countCitations(text: string): number {
    return sourceNames.filter(name => text.includes(name)).length;
  }

  if (resolvedModel) {
    const prompt = buildAnalysisPrompt(ioc, workflowId, results, overall, contradictions);
    try {
      narrative = await ollamaGenerate(resolvedModel, prompt);
      // Retry once if fewer than 2 sources are cited and we have enough data
      if (narrative && countCitations(narrative) < 2 && successful.length >= 2) {
        citationRetried = true;
        const retryPrompt = `IMPORTANT: Your previous response did not cite sources by name. You MUST cite at least 2 sources using [SourceName] brackets in KEY FINDINGS. Available sources: ${sourceNames.join(', ')}.\n\n${prompt}`;
        try {
          const retried = await ollamaGenerate(resolvedModel, retryPrompt);
          if (retried) narrative = retried;
        } catch { /* keep original if retry fails */ }
      }
    } catch (err) {
      const isTimeout = err instanceof Error && err.name === 'AbortError';
      narrativeError = isTimeout
        ? 'Ollama timed out generating the narrative. Try again or use a faster model.'
        : err instanceof Error ? err.message : 'Unknown error from Ollama.';
    }
  } else {
    narrativeError = 'Ollama is not running or the model is not available. Start Ollama and ensure qwen2.5 is pulled.';
  }

  const effectiveModel = resolvedModel ?? ollamaModel;

  const response: EnrichmentResponse & {
    narrative: string | null;
    narrativeError?: string;
    ollamaModel: string;
    ollamaAvailable: boolean;
    analysedAt: string;
    contradictions: ContradictionFlag[];
    citationRetried: boolean;
  } = {
    ioc,
    results,
    overall,
    narrative,
    narrativeError,
    ollamaModel: effectiveModel,
    ollamaAvailable: resolvedModel !== null,
    analysedAt: new Date().toISOString(),
    contradictions,
    citationRetried,
  };

  res.json(response);
});

export default router;
