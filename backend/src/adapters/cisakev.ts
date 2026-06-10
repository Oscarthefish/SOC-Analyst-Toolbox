import fetch from 'node-fetch';
import type { IocInput, EnrichmentResult, EnrichOptions } from '../types.js';
import { computeFreshness } from '../lib/freshness.js';

const PROVIDER_ID = 'cisakev';
const PROVIDER_NAME = 'CISA KEV';
const TIMEOUT_MS = 15_000;
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

function now(): string { return new Date().toISOString(); }

function makeResult(overrides: Partial<EnrichmentResult>): EnrichmentResult {
  return {
    providerId: PROVIDER_ID, providerName: PROVIDER_NAME,
    status: 'ok', summary: '', severity: 'unknown', confidence: 'unknown',
    data: {}, rawAvailable: false, checkedAt: now(), fromCache: false,
    ...overrides,
  };
}

interface KevVulnerability {
  cveID?: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  dateAdded?: string;
  shortDescription?: string;
  requiredAction?: string;
  dueDate?: string;
  knownRansomwareCampaignUse?: string;
}

interface KevResponse {
  title?: string;
  dateReleased?: string;
  count?: number;
  vulnerabilities?: KevVulnerability[];
}

// Module-level cache to avoid re-fetching on every CVE lookup within a request batch
let kevData: KevVulnerability[] | null = null;
let kevFetchedAt = 0;
const KEV_MEM_TTL_MS = 55 * 60 * 1000; // 55 minutes (slightly under disk cache TTL)

async function fetchKevData(): Promise<KevVulnerability[]> {
  if (kevData && Date.now() - kevFetchedAt < KEV_MEM_TTL_MS) {
    return kevData;
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(KEV_URL, { signal: controller.signal });
    clearTimeout(timeout);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const json = (await res.json()) as KevResponse;
    kevData = json.vulnerabilities ?? [];
    kevFetchedAt = Date.now();
    return kevData;
  } catch (err) {
    clearTimeout(timeout);
    throw err;
  }
}

export async function cisakev(ioc: IocInput, _options: EnrichOptions): Promise<EnrichmentResult> {
  if (ioc.type !== 'cve') {
    return makeResult({
      status: 'unsupported_ioc',
      summary: `CISA KEV only supports CVE IDs (type: cve).`,
    });
  }

  const cveId = ioc.normalised.toUpperCase();

  try {
    const vulns = await fetchKevData();
    const match = vulns.find(v => (v.cveID ?? '').toUpperCase() === cveId);

    if (!match) {
      return makeResult({
        status: 'ok',
        summary: `CISA KEV: ${cveId} is NOT in the Known Exploited Vulnerabilities catalogue.`,
        severity: 'unknown',
        confidence: 'high',
        sourceReliability: 'authoritative',
        freshnessLabel: 'unknown',
        keyFacts: [
          { label: 'In CISA KEV', value: 'No' },
        ],
        data: { inKev: false, cveId },
        sourceUrl: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      });
    }

    const dateAdded = match.dateAdded;
    const product = [match.vendorProject, match.product].filter(Boolean).join(' — ');
    const ransomware = match.knownRansomwareCampaignUse === 'Known' ? 'yes' : 'no';

    const summary = `CISA KEV: ${cveId} IS in the Known Exploited Vulnerabilities catalogue. ` +
      `Product: ${product || 'unknown'}. ` +
      `Added to KEV: ${dateAdded ?? 'unknown'}. ` +
      `Ransomware use: ${ransomware}. ` +
      (match.requiredAction ? `Required action: ${match.requiredAction}` : '');

    return makeResult({
      status: 'ok',
      summary,
      severity: 'critical',
      confidence: 'high',
      sourceReliability: 'authoritative',
      lastSeenDate: dateAdded ? new Date(dateAdded).toISOString() : undefined,
      firstSeenDate: dateAdded ? new Date(dateAdded).toISOString() : undefined,
      freshnessLabel: computeFreshness(dateAdded ? new Date(dateAdded).toISOString() : undefined),
      keyFacts: [
        { label: 'In CISA KEV', value: 'YES — actively exploited' },
        ...(product ? [{ label: 'Product', value: product }] : []),
        ...(dateAdded ? [{ label: 'Date added to KEV', value: dateAdded }] : []),
        ...(match.dueDate ? [{ label: 'Remediation due', value: match.dueDate }] : []),
        { label: 'Ransomware use', value: ransomware },
        ...(match.requiredAction ? [{ label: 'Required action', value: match.requiredAction }] : []),
        ...(match.vulnerabilityName ? [{ label: 'Vulnerability', value: match.vulnerabilityName }] : []),
      ],
      data: {
        inKev: true,
        cveId,
        vendorProject: match.vendorProject,
        product: match.product,
        vulnerabilityName: match.vulnerabilityName,
        dateAdded,
        dueDate: match.dueDate,
        requiredAction: match.requiredAction,
        knownRansomwareCampaignUse: match.knownRansomwareCampaignUse,
        shortDescription: match.shortDescription,
      },
      rawAvailable: true,
      sourceUrl: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`,
    });
  } catch (err) {
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({
      status: 'error',
      summary: isTimeout ? 'CISA KEV request timed out.' : 'CISA KEV request failed.',
      errorMessage: err instanceof Error ? err.message : String(err),
    });
  }
}
