import { Router } from 'express';
import type { Request, Response } from 'express';
import type {
  IocInput,
  IocType,
  EnrichRequest,
  EnrichmentResult,
  EnrichmentResponse,
  OverallAssessment,
  EnrichOptions,
  Severity,
  Confidence,
} from '../types.js';
import { adapters } from '../adapters/index.js';
import { config } from '../config.js';
import * as cache from '../cache.js';
import { isRateLimited, recordRequest } from '../rateLimit.js';

const router = Router();

const VALID_IOC_TYPES: IocType[] = [
  'ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email', 'asn', 'cidr', 'cve', 'secret',
];

// Default provider selection per workflow ID
const WORKFLOW_PROVIDERS: Record<string, string[]> = {
  'ip-triage': ['greynoise', 'abuseipdb', 'ipapi', 'torproject', 'ipinfo', 'virustotal', 'shodan', 'censys'],
  'waf-web-attack': ['greynoise', 'abuseipdb', 'ipapi', 'torproject', 'ipinfo', 'virustotal', 'shodan'],
  'suspicious-connection': ['virustotal', 'greynoise', 'abuseipdb', 'ipapi', 'torproject', 'ipinfo', 'shodan', 'censys'],
  'domain-triage': ['dns', 'crtsh', 'wayback', 'virustotal', 'urlscan', 'censys', 'hudsonrock', 'emailsecurity', 'identityfabric'],
  'business-domain-osint': ['dns', 'crtsh', 'wayback', 'whois', 'hudsonrock', 'emailsecurity', 'identityfabric'],
  'url-phishing': ['urlscan', 'virustotal'],
  'malware-hash': ['virustotal'],
  'spam-source': ['greynoise', 'abuseipdb', 'ipapi', 'torproject', 'ipinfo'],
  'dark-web-exposure': [],
  'ransomware-context': ['virustotal'],
  'external-exposure': ['shodan', 'censys'],
  'email-header-review': [],
};

// Default providers by IOC type (used when workflow is unknown)
const IOC_TYPE_PROVIDERS: Record<IocType, string[]> = {
  ipv4: ['greynoise', 'abuseipdb', 'ipapi', 'torproject', 'ipinfo', 'virustotal', 'shodan', 'censys'],
  ipv6: ['greynoise', 'abuseipdb', 'ipapi', 'torproject', 'ipinfo', 'virustotal', 'censys'],
  domain: ['dns', 'dnsdumpster', 'crtsh', 'wayback', 'virustotal', 'urlscan', 'hudsonrock', 'emailsecurity', 'identityfabric'],
  url: ['urlscan', 'virustotal'],
  md5: ['virustotal'],
  sha1: ['virustotal'],
  sha256: ['virustotal'],
  email: [],
  asn: [],
  cidr: [],
  cve: ['cisakev'],
  // credvalidate sends the credential to its issuer, so it is never a default
  secret: [],
};

/** Providers that transmit the IOC itself as a credential and need explicit opt-in. */
const HIGH_RISK_PROVIDERS = new Set(['credvalidate']);

function chooseProviders(
  ioc: IocInput,
  workflowId: string | undefined,
  requestedProviders: string[] | undefined,
): string[] {
  if (requestedProviders && requestedProviders.length > 0) {
    return requestedProviders.filter(p => p in adapters);
  }
  if (workflowId && workflowId in WORKFLOW_PROVIDERS) {
    return WORKFLOW_PROVIDERS[workflowId] ?? [];
  }
  return IOC_TYPE_PROVIDERS[ioc.type] ?? [];
}

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  benign: 1,
  unknown: 0,
};

function detectContradictions(results: EnrichmentResult[]): string[] {
  const meaningful = results.filter(
    r => (r.status === 'ok' || r.status === 'cached') && r.severity !== 'unknown',
  );
  if (meaningful.length < 2) return [];

  const malicious = meaningful.filter(r => SEVERITY_RANK[r.severity] >= 4);
  const benign = meaningful.filter(r => r.severity === 'benign');

  if (malicious.length > 0 && benign.length > 0) {
    const maliciousNames = malicious.map(r => r.providerName).join(', ');
    const benignNames = benign.map(r => r.providerName).join(', ');
    return [
      `Provider disagreement: ${maliciousNames} rates this IOC as high/critical, while ${benignNames} considers it benign. Treat with caution — cross-reference raw data from each provider and consider manual investigation before taking action.`,
    ];
  }

  return [];
}

function computeOverallAssessment(results: EnrichmentResult[]): OverallAssessment {
  const successful = results.filter(
    r => r.status === 'ok' || r.status === 'cached',
  );

  const severityCounts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    benign: 0,
    unknown: 0,
  };

  for (const r of successful) {
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

  // Confidence based on how many providers succeeded
  let confidence: Confidence;
  const successCount = successful.length;
  if (successCount >= 3) {
    confidence = 'high';
  } else if (successCount >= 1) {
    confidence = 'medium';
  } else {
    confidence = 'low';
  }

  const severityLabel = severity.charAt(0).toUpperCase() + severity.slice(1);
  let summary =
    successful.length === 0
      ? 'No enrichment providers returned data. Check API key configuration.'
      : `Aggregated assessment from ${successful.length} provider(s): ${severityLabel} severity, ${confidence} confidence.`;

  const contradictions = detectContradictions(results);
  if (contradictions.length > 0) {
    summary += ' ⚠ Provider disagreement detected — see recommended actions.';
    recommendedActions.push(...contradictions);
  }

  return { severity, confidence, summary, recommendedActions };
}

router.post('/enrich', async (req: Request, res: Response): Promise<void> => {
  const body = req.body as Partial<EnrichRequest>;

  // Validate
  if (!body.ioc) {
    res.status(400).json({ error: 'ioc field is required.' });
    return;
  }

  if (!VALID_IOC_TYPES.includes(body.ioc.type)) {
    res.status(400).json({ error: `Invalid IOC type: ${body.ioc.type}. Must be one of: ${VALID_IOC_TYPES.join(', ')}.` });
    return;
  }

  if (!body.ioc.normalised) {
    res.status(400).json({ error: 'ioc.normalised is required.' });
    return;
  }

  const ioc: IocInput = body.ioc;
  const workflowId = body.workflowId;
  const requestedProviders = body.providers;
  const options = body.options ?? {};

  const includeHunter = options.includeHunter ?? false;

  const enrichOptions: EnrichOptions = {
    forceRefresh: options.forceRefresh ?? false,
    allowSensitiveUrl: options.allowSensitiveUrl ?? false,
    allowUrlSubmission: (options.allowUrlSubmission ?? false) && config.enableUrlSubmission,
    includeRaw: options.includeRaw ?? false,
    includeHunter,
  };

  let providerList = chooseProviders(ioc, workflowId, requestedProviders);

  const wantsHighRisk = providerList.filter(p => HIGH_RISK_PROVIDERS.has(p));
  if (wantsHighRisk.length > 0) {
    if (!config.enableHighRiskEnrichment || options.allowCredentialValidation !== true) {
      res.status(403).json({
        error: `${wantsHighRisk.join(', ')} requires ENABLE_HIGH_RISK_ENRICHMENT=true in backend/.env and options.allowCredentialValidation=true on the request.`,
      });
      return;
    }
    if (ioc.type !== 'secret') {
      res.status(400).json({ error: 'credvalidate only accepts IOCs of type "secret".' });
      return;
    }
  }
  if (includeHunter && (ioc.type === 'domain' || ioc.type === 'url' || ioc.type === 'email') && !providerList.includes('hunter')) {
    providerList = [...providerList, 'hunter'];
  }

  if (providerList.length === 0) {
    const overall = computeOverallAssessment([]);
    const response: EnrichmentResponse = {
      ioc,
      results: [],
      overall: {
        ...overall,
        summary: `No enrichment providers are configured for IOC type "${ioc.type}"${workflowId ? ` with workflow "${workflowId}"` : ''}.`,
      },
    };
    res.json(response);
    return;
  }

  // Run providers in parallel
  const promises = providerList.map(async (providerId): Promise<EnrichmentResult> => {
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

    // Check cache first
    const isSensitiveUrl = ioc.type === 'url';
    const cacheKey = cache.buildCacheKey(providerId, ioc.type, ioc.normalised, isSensitiveUrl);

    if (!enrichOptions.forceRefresh && !HIGH_RISK_PROVIDERS.has(providerId)) {
      const cached = cache.get(cacheKey);
      if (cached) {
        return cached;
      }
    }

    // Check rate limit
    if (isRateLimited(providerId)) {
      return {
        providerId,
        providerName: providerId,
        status: 'rate_limited',
        summary: `${providerId} is currently rate-limited. Try again in 60 seconds.`,
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
      const result = await adapter(ioc, enrichOptions);
      // Cache successful results and missing_key (don't hammer missing keys)
      if ((result.status === 'ok' || result.status === 'missing_key') && !HIGH_RISK_PROVIDERS.has(providerId)) {
        cache.set(cacheKey, result, config.cacheTtlMinutes);
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
  });

  const settled = await Promise.allSettled(promises);
  const results: EnrichmentResult[] = settled.map((s, i) => {
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

  const overall = computeOverallAssessment(results);
  const response: EnrichmentResponse = { ioc, results, overall };

  res.json(response);
});

export default router;
