import type { IocInput, EnrichmentResult, EnrichOptions, Severity } from '../types.js';

const PROVIDER_ID = 'hudsonrock';
const PROVIDER_NAME = 'HudsonRock Cavalier';
const TIMEOUT_MS = 12_000;

function now(): string {
  return new Date().toISOString();
}

function makeResult(overrides: Partial<EnrichmentResult>): EnrichmentResult {
  return {
    providerId: PROVIDER_ID,
    providerName: PROVIDER_NAME,
    status: 'ok',
    summary: '',
    severity: 'unknown',
    confidence: 'unknown',
    data: {},
    rawAvailable: false,
    checkedAt: now(),
    fromCache: false,
    ...overrides,
  };
}

interface CavalierTotal {
  employees?: number;
  users?: number;
  third_parties?: number;
}

interface CavalierResponse {
  message?: string;
  have_data?: boolean;
  total?: CavalierTotal;
  data?: {
    employees?: Array<{ url?: string; computer_name?: string; date_uploaded?: string }>;
    users?: Array<{ url?: string }>;
    stealers?: string[];
    stealer_families?: Record<string, number>;
  };
}

export async function hudsonrock(
  ioc: IocInput,
  _options: EnrichOptions,
): Promise<EnrichmentResult> {
  if (ioc.type !== 'domain') {
    return makeResult({
      status: 'unsupported_ioc',
      summary: `HudsonRock Cavalier does not support IOC type: ${ioc.type} (supports: domain).`,
    });
  }

  const domain = ioc.normalised;
  const url = `https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=${encodeURIComponent(domain)}`;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        Accept: 'application/json',
        'User-Agent': 'SOC-Analyst-Toolbox/1.0',
      },
    });
    clearTimeout(timeout);

    if (res.status === 429) {
      return makeResult({
        status: 'rate_limited',
        summary: 'HudsonRock Cavalier rate limit reached. Try again in a few minutes.',
      });
    }
    if (!res.ok) {
      return makeResult({
        status: 'error',
        summary: `HudsonRock Cavalier returned HTTP ${res.status}.`,
        errorMessage: `HTTP ${res.status}`,
      });
    }

    const body = (await res.json()) as CavalierResponse;
    const employees = body.total?.employees ?? 0;
    const users = body.total?.users ?? 0;

    if (!body.have_data || (employees === 0 && users === 0)) {
      return makeResult({
        status: 'ok',
        summary: `HudsonRock Cavalier: No infostealer records found for ${domain}.`,
        severity: 'unknown',
        confidence: 'medium',
        data: { employees: 0, users: 0 },
        sourceReliability: 'commercial-ti',
        sourceUrl: `https://www.hudsonrock.com/search?domain=${domain}`,
        keyFacts: [
          { label: 'Employee accounts', value: '0' },
          { label: 'User accounts', value: '0' },
        ],
      });
    }

    const stealerFamilies = body.data?.stealer_families ?? {};
    const stealerList = Object.keys(stealerFamilies).join(', ') || 'unknown';

    let severity: Severity;
    if (employees >= 10) {
      severity = 'critical';
    } else if (employees >= 1) {
      severity = 'high';
    } else if (users >= 1) {
      severity = 'medium';
    } else {
      severity = 'low';
    }

    const parts: string[] = [];
    if (employees > 0) parts.push(`${employees} employee account(s)`);
    if (users > 0) parts.push(`${users} customer/user account(s)`);

    return makeResult({
      status: 'ok',
      summary: `HudsonRock Cavalier: ${parts.join(' and ')} compromised via infostealer malware for ${domain}. Families: ${stealerList}.`,
      severity,
      confidence: 'high',
      data: { employees, users, stealerFamilies },
      sourceReliability: 'commercial-ti',
      sourceUrl: `https://www.hudsonrock.com/search?domain=${domain}`,
      keyFacts: [
        { label: 'Employee accounts', value: String(employees) },
        { label: 'User accounts', value: String(users) },
        ...(stealerList !== 'unknown' ? [{ label: 'Stealer families', value: stealerList }] : []),
      ],
    });
  } catch (err) {
    clearTimeout(timeout);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({
      status: 'error',
      summary: isTimeout
        ? 'HudsonRock Cavalier request timed out.'
        : 'HudsonRock Cavalier request failed.',
      errorMessage: err instanceof Error ? err.message : String(err),
    });
  }
}
