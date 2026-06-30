import fetch from 'node-fetch';
import type { IocInput, EnrichmentResult, EnrichOptions, Severity } from '../types.js';
import { config } from '../config.js';

const PROVIDER_ID = 'hunter';
const PROVIDER_NAME = 'Hunter.io';
const TIMEOUT_MS = 12_000;

function now(): string { return new Date().toISOString(); }

function makeResult(overrides: Partial<EnrichmentResult>): EnrichmentResult {
  return {
    providerId: PROVIDER_ID, providerName: PROVIDER_NAME,
    status: 'ok', summary: '', severity: 'unknown', confidence: 'unknown',
    data: {}, rawAvailable: false, checkedAt: now(), fromCache: false,
    ...overrides,
  };
}

// ── Domain Search ─────────────────────────────────────────────────────────────

interface HunterDomainData {
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

interface HunterDomainResponse {
  data?: HunterDomainData;
  errors?: Array<{ id?: string; details?: string }>;
}

async function hunterDomainSearch(domain: string, apiKey: string): Promise<EnrichmentResult> {
  const url = `https://api.hunter.io/v2/domain-search?domain=${encodeURIComponent(domain)}&limit=1&api_key=${apiKey}`;
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

    const body = (await res.json()) as HunterDomainResponse;
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

    const severity: Severity = isDisposable ? 'medium' : 'unknown';

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
      status: 'ok', summary, severity,
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
        ...([city, country].filter(Boolean).length > 0
          ? [{ label: 'Location', value: [city, country].filter(Boolean).join(', ') }] : []),
        ...(emailCount > 0 ? [{ label: 'Indexed emails', value: String(emailCount) }] : []),
        ...(isDisposable ? [{ label: 'Disposable', value: 'Yes — throwaway email service' }] : []),
        ...(isWebmail ? [{ label: 'Webmail', value: 'Yes (Gmail / Outlook / etc.)' }] : []),
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

// ── Email Verifier + Person Enrichment ───────────────────────────────────────

interface HunterVerifyData {
  status?: string;   // valid | invalid | accept_all | webmail | disposable | unknown
  result?: string;   // deliverable | undeliverable | risky
  score?: number;
  email?: string;
  regexp?: boolean;
  gibberish?: boolean;
  disposable?: boolean;
  webmail?: boolean;
  mx_records?: boolean;
  smtp_server?: boolean;
  smtp_check?: boolean;
  accept_all?: boolean;
  block?: boolean;
  sources?: Array<{ domain?: string; uri?: string; last_seen_on?: string; still_on_page?: boolean }>;
}

interface HunterVerifyResponse {
  data?: HunterVerifyData;
  errors?: Array<{ id?: string; details?: string }>;
}

interface HunterPersonData {
  name?: { fullName?: string; givenName?: string; familyName?: string };
  email?: string;
  location?: string;
  bio?: string | null;
  employment?: { domain?: string; name?: string; title?: string; role?: string; seniority?: string };
  social_handles?: {
    twitter?: { handle?: string | null };
    linkedin?: { handle?: string | null };
    github?: { handle?: string | null };
  };
  phone?: string | null;
}

interface HunterPersonResponse {
  data?: HunterPersonData;
  errors?: Array<{ id?: string; details?: string }>;
}

async function hunterEmailEnrich(email: string, apiKey: string): Promise<EnrichmentResult> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const [verifyRes, personRes] = await Promise.all([
      fetch(`https://api.hunter.io/v2/email-verifier?email=${encodeURIComponent(email)}&api_key=${apiKey}`,
        { signal: controller.signal, headers: { Accept: 'application/json' } }),
      fetch(`https://api.hunter.io/v2/people/find?email=${encodeURIComponent(email)}&api_key=${apiKey}`,
        { signal: controller.signal, headers: { Accept: 'application/json' } }),
    ]);
    clearTimeout(timeout);

    if ([verifyRes.status, personRes.status].some(s => s === 401 || s === 403)) {
      return makeResult({ status: 'missing_key', summary: 'Hunter.io: Invalid or expired API key.' });
    }
    if ([verifyRes.status, personRes.status].some(s => s === 429)) {
      return makeResult({ status: 'rate_limited', summary: 'Hunter.io rate limit reached (free tier: 25/month).' });
    }

    let verifyData: HunterVerifyData | null = null;
    if (verifyRes.ok || verifyRes.status === 202) {
      const body = (await verifyRes.json()) as HunterVerifyResponse;
      verifyData = body.data ?? null;
    }

    let personData: HunterPersonData | null = null;
    if (personRes.ok) {
      const body = (await personRes.json()) as HunterPersonResponse;
      personData = body.data ?? null;
    }

    if (!verifyData && !personData) {
      return makeResult({ status: 'ok', summary: `Hunter.io: No data found for ${email}.`, severity: 'unknown', confidence: 'low', data: {} });
    }

    const status  = verifyData?.status  ?? 'unknown';
    const result  = verifyData?.result  ?? 'unknown';
    const score   = verifyData?.score   ?? null;
    const isDisposable = verifyData?.disposable ?? false;
    const isGibberish  = verifyData?.gibberish  ?? false;
    const isBlocked    = verifyData?.block      ?? false;
    const sources      = verifyData?.sources    ?? [];

    const severity: Severity = isDisposable ? 'medium' : result === 'undeliverable' ? 'low' : 'unknown';

    const fullName   = personData?.name?.fullName ?? null;
    const employer   = personData?.employment?.name ?? null;
    const title      = personData?.employment?.title ?? null;
    const location   = personData?.location ?? null;
    const twitterH   = personData?.social_handles?.twitter?.handle ?? null;
    const linkedinH  = personData?.social_handles?.linkedin?.handle ?? null;

    const parts: string[] = [`Status: ${status.toUpperCase()} (${result})`];
    if (score !== null) parts.push(`confidence ${score}%`);
    if (isDisposable) parts.push('DISPOSABLE address');
    if (isGibberish)  parts.push('gibberish local-part');
    if (isBlocked)    parts.push('blocked by provider');
    if (fullName)     parts.push(`owner: ${fullName}${employer ? ` @ ${employer}` : ''}`);
    if (sources.length) parts.push(`${sources.length} web source(s)`);

    return makeResult({
      status: 'ok',
      summary: `Hunter.io email: ${parts.join(', ')}.`,
      severity,
      confidence: score !== null ? (score >= 70 ? 'high' : 'medium') : 'low',
      data: {
        emailStatus: status, emailResult: result, score,
        isDisposable, isGibberish, isBlocked,
        isWebmail: verifyData?.webmail ?? false,
        mxRecords: verifyData?.mx_records ?? false,
        smtpCheck: verifyData?.smtp_check ?? false,
        acceptAll: verifyData?.accept_all ?? false,
        sourceCount: sources.length,
        person: personData ? { fullName, employer, title, location } : null,
      },
      rawAvailable: true,
      sourceUrl: `https://hunter.io/verify/${encodeURIComponent(email)}`,
      sourceReliability: 'community',
      keyFacts: [
        { label: 'Email status', value: `${status.toUpperCase()} — ${result}` },
        ...(score !== null ? [{ label: 'Confidence', value: `${score}%` }] : []),
        ...(isDisposable ? [{ label: 'Disposable', value: 'Yes — throwaway address' }] : []),
        ...(isGibberish  ? [{ label: 'Gibberish', value: 'Yes — randomised local-part' }] : []),
        ...(verifyData?.webmail ? [{ label: 'Webmail', value: 'Yes' }] : []),
        ...(fullName  ? [{ label: 'Name', value: fullName }] : []),
        ...(employer  ? [{ label: 'Employer', value: employer + (title ? ` — ${title}` : '') }] : []),
        ...(location  ? [{ label: 'Location', value: location }] : []),
        ...(twitterH  ? [{ label: 'Twitter', value: `@${twitterH}` }] : []),
        ...(linkedinH ? [{ label: 'LinkedIn', value: linkedinH }] : []),
        ...(sources.length ? [{ label: 'Web sources', value: String(sources.length) }] : []),
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

// ── Main export ───────────────────────────────────────────────────────────────

export async function hunter(ioc: IocInput, _options: EnrichOptions): Promise<EnrichmentResult> {
  const apiKey = config.hunter.apiKey;
  if (!apiKey) {
    return makeResult({ status: 'missing_key', summary: 'Hunter.io API key not configured. Register free at hunter.io.' });
  }

  if (ioc.type === 'domain') {
    return hunterDomainSearch(ioc.normalised, apiKey);
  }

  if (ioc.type === 'url') {
    let domain = ioc.normalised;
    try {
      domain = new URL(ioc.normalised.startsWith('http') ? ioc.normalised : `https://${ioc.normalised}`).hostname;
    } catch { /* fall back to raw value */ }
    return hunterDomainSearch(domain, apiKey);
  }

  if (ioc.type === 'email') {
    return hunterEmailEnrich(ioc.normalised, apiKey);
  }

  return makeResult({
    status: 'unsupported_ioc',
    summary: `Hunter.io does not support IOC type: ${ioc.type} (supports: domain, url, email).`,
  });
}
