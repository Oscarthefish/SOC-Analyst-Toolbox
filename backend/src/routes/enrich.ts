import { Router } from 'express';
import type { Request, Response } from 'express';
import type {
  IocInput,
  IocType,
  EnrichRequest,
  EnrichmentResult,
  EnrichmentResponse,
  EnrichOptions,
} from '../types.js';
import { adapters } from '../adapters/index.js';
import { config } from '../config.js';
import * as cache from '../cache.js';
import { acquire } from '../rateLimit.js';
import { computeOverallAssessment, detectContradictions, detectVpnOrTor } from '../lib/scoring.js';

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
    // Waits briefly for a free slot; gives up if the provider is paused or saturated
    const retryInMs = await acquire(providerId);
    if (retryInMs > 0) {
      return {
        providerId,
        providerName: providerId,
        status: 'rate_limited',
        summary: `${providerId} is rate-limited. Try again in ${Math.ceil(retryInMs / 1000)} s.`,
        severity: 'unknown',
        confidence: 'unknown',
        data: {},
        rawAvailable: false,
        checkedAt: new Date().toISOString(),
        fromCache: false,
      };
    }

    try {
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

  const contradictions = detectContradictions(results);
  const overall = computeOverallAssessment(results, detectVpnOrTor(results));
  const response: EnrichmentResponse = { ioc, results, overall, contradictions };

  res.json(response);
});

export default router;
