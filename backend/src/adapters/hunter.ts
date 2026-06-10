import fetch from 'node-fetch';
import type { IocInput, EnrichmentResult, EnrichOptions } from '../types.js';
import { config } from '../config.js';

const PROVIDER_ID = 'hunter';
const PROVIDER_NAME = 'Hunter.io';
const TIMEOUT_MS = 10_000;

function now(): string { return new Date().toISOString(); }

function makeResult(overrides: Partial<EnrichmentResult>): EnrichmentResult {
  return {
    providerId: PROVIDER_ID, providerName: PROVIDER_NAME,
    status: 'ok', summary: '', severity: 'unknown', confidence: 'unknown',
    data: {}, rawAvailable: false, checkedAt: now(), fromCache: false,
    ...overrides,
  };
}

interface HunterData {
  domain?: string;
  disposable?: boolean;
  webmail?: boolean;
  accept_all?: boolean;
  pattern?: string;
  organization?: string | null;
  description?: string | null;
  industry?: string | null;
  twitter?: string | null;
  linkedin?: string | null;
  technologies?: string[];
  country?: string | null;
  state?: string | null;
  city?: string | null;
  headcount?: string | null;
  company_type?: string | null;
  meta?: { results?: number };
}

interface HunterResponse {
  data?: HunterData;
  errors?: Array<{ id?: string; details?: string }>;
}

export async function hunter(ioc: IocInput, _options: EnrichOptions): Promise<EnrichmentResult> {
  if (ioc.type !== 'domain') {
    return makeResult({
      status: 'unsupported_ioc',
      summary: `Hunter.io does not support IOC type: ${ioc.type} (supports: domain).`,
    });
  }

  const apiKey = config.hunter.apiKey;
  if (!apiKey) {
    return makeResult({ status: 'missing_key', summary: 'Hunter.io API key not configured. Register free at hunter.io.' });
  }

  const domain = ioc.normalised;
  const url = `https://api.hunter.io/v2/domain-search?domain=${encodeURIComponent(domain)}&limit=0&api_key=${apiKey}`;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(url, { signal: controller.signal, headers: { Accept: 'application/json' } });
    clearTimeout(timeout);

    if (res.status === 401 || res.status === 403) {
      return makeResult({ status: 'missing_key', summary: 'Hunter.io: Invalid or expired API key.', errorMessage: `HTTP ${res.status}` });
    }
    if (res.status === 429) {
      return makeResult({ status: 'rate_limited', summary: 'Hunter.io rate limit reached (free tier: 25/month).' });
    }
    if (!res.ok) {
      return makeResult({ status: 'error', summary: `Hunter.io returned HTTP ${res.status}.`, errorMessage: `HTTP ${res.status}` });
    }

    const body = (await res.json()) as HunterResponse;
    if (body.errors?.length) {
      return makeResult({ status: 'error', summary: `Hunter.io error: ${body.errors[0]?.details ?? 'Unknown'}`, errorMessage: body.errors[0]?.details });
    }

    const d = body.data;
    if (!d) {
      return makeResult({ status: 'ok', summary: 'Hunter.io: No data returned for this domain.', severity: 'unknown', confidence: 'low', data: {} });
    }

    const org = d.organization ?? null;
    const industry = d.industry ?? null;
    const headcount = d.headcount ?? null;
    const country = d.country ?? null;
    const city = d.city ?? null;
    const emailPattern = d.pattern ?? null;
    const emailCount = d.meta?.results ?? 0;
    const isDisposable = d.disposable ?? false;
    const isWebmail = d.webmail ?? false;
    const linkedinUrl = d.linkedin ?? null;

    // Severity logic: disposable = medium (used for throwaway accounts)
    // No org found = suspicious for a domain claiming business legitimacy
    // Otherwise passive context only
    const severity = isDisposable ? 'medium' : 'unknown';

    let summary: string;
    if (isDisposable) {
      summary = `Hunter.io: ${domain} is a DISPOSABLE email provider — commonly used to evade tracking.`;
    } else if (!org) {
      summary = `Hunter.io: No company identified for ${domain}. May be a personal, privacy-protected, or newly registered domain.`;
    } else {
      const location = [city, country].filter(Boolean).join(', ');
      summary = `Hunter.io: ${org}${industry ? ` (${industry})` : ''}${headcount ? `, ~${headcount} employees` : ''}${location ? `, ${location}` : ''}.${emailCount > 0 ? ` ${emailCount} email(s) indexed.` : ''}`;
    }

    return makeResult({
      status: 'ok',
      summary,
      severity,
      confidence: org ? 'high' : 'medium',
      data: { org, industry, headcount, country, city, emailPattern, emailCount, isDisposable, isWebmail, linkedinUrl },
      rawAvailable: true,
      sourceUrl: `https://hunter.io/search/${encodeURIComponent(domain)}`,
      sourceReliability: 'community',
      keyFacts: [
        { label: 'Company', value: org ?? (isDisposable ? 'Disposable provider' : 'Not identified') },
        ...(industry ? [{ label: 'Industry', value: industry }] : []),
        ...(headcount ? [{ label: 'Employees', value: headcount }] : []),
        ...(emailPattern ? [{ label: 'Email pattern', value: emailPattern }] : []),
        ...([city, country].filter(Boolean).length > 0 ? [{ label: 'Location', value: [city, country].filter(Boolean).join(', ') }] : []),
        ...(emailCount > 0 ? [{ label: 'Indexed emails', value: String(emailCount) }] : []),
        ...(isDisposable ? [{ label: 'Disposable provider', value: 'Yes — throwaway email service' }] : []),
        ...(isWebmail ? [{ label: 'Webmail provider', value: 'Yes (Gmail/Outlook/etc.)' }] : []),
        ...(linkedinUrl ? [{ label: 'LinkedIn', value: linkedinUrl }] : []),
      ],
    });
  } catch (err) {
    clearTimeout(timeout);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({
      status: 'error',
      summary: isTimeout ? 'Hunter.io request timed out.' : 'Hunter.io request failed.',
      errorMessage: err instanceof Error ? err.message : String(err),
    });
  }
}
