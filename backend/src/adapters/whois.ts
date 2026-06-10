import fetch from 'node-fetch';
import type { IocInput, EnrichmentResult, EnrichOptions, Severity } from '../types.js';
import { config } from '../config.js';

const PROVIDER_ID = 'whois';
const PROVIDER_NAME = 'WHOIS';
const TIMEOUT_MS = 12_000;
const RDAP_BASE = 'https://rdap.org';
const WHOISXML_BASE = 'https://www.whoisxmlapi.com/whoisserver/WhoisService';

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

function getDomainAge(dateStr: string | undefined | null): number | null {
  if (!dateStr) return null;
  try {
    return Math.floor((Date.now() - new Date(dateStr).getTime()) / 86_400_000);
  } catch {
    return null;
  }
}

function domainSeverity(domainAge: number | null): Severity {
  if (domainAge === null) return 'unknown';
  if (domainAge < 30) return 'medium';
  if (domainAge < 180) return 'low';
  return 'benign';
}

// --- WhoisXML API ---

interface WhoisXmlRegistrant {
  name?: string;
  organization?: string;
  country?: string;
}

interface WhoisXmlNameServers {
  hostNames?: string[];
}

interface WhoisXmlRecord {
  domainName?: string;
  createdDate?: string;
  updatedDate?: string;
  expiresDate?: string;
  domainAge?: number;
  registrarName?: string;
  registrant?: WhoisXmlRegistrant;
  administrativeContact?: WhoisXmlRegistrant;
  nameServers?: WhoisXmlNameServers;
  status?: string;
  parseCode?: number;
}

interface WhoisXmlResponse {
  WhoisRecord?: WhoisXmlRecord;
  ErrorMessage?: { errorCode?: string; msg?: string };
}

async function queryWhoisXml(ioc: IocInput, apiKey: string): Promise<EnrichmentResult> {
  const url = `${WHOISXML_BASE}?apiKey=${encodeURIComponent(apiKey)}&domainName=${encodeURIComponent(ioc.normalised)}&outputFormat=JSON&ignoreRawTexts=1`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(url, { signal: controller.signal });
    clearTimeout(timeout);

    if (res.status === 401 || res.status === 403) {
      return makeResult({
        status: 'error',
        summary: 'WhoisXML API: invalid or unauthorised API key.',
        errorMessage: `HTTP ${res.status}`,
      });
    }

    if (!res.ok) {
      return makeResult({
        status: 'error',
        summary: `WhoisXML API returned HTTP ${res.status}.`,
        errorMessage: `HTTP ${res.status}`,
      });
    }

    const body = (await res.json()) as WhoisXmlResponse;

    if (body.ErrorMessage) {
      return makeResult({
        status: 'error',
        summary: `WhoisXML API error: ${body.ErrorMessage.msg ?? body.ErrorMessage.errorCode ?? 'unknown'}.`,
        errorMessage: body.ErrorMessage.msg ?? body.ErrorMessage.errorCode,
      });
    }

    const rec = body.WhoisRecord;
    if (!rec) {
      return makeResult({
        status: 'ok',
        summary: 'WHOIS: No registration data found.',
        severity: 'unknown',
        confidence: 'low',
        data: { notFound: true },
      });
    }

    if (ioc.type === 'domain') {
      const domainAge = rec.domainAge ?? getDomainAge(rec.createdDate);
      const severity = domainSeverity(domainAge);
      const registrant = rec.registrant ?? rec.administrativeContact;
      const registrantOrg = registrant?.organization ?? registrant?.name ?? null;
      const nameservers = rec.nameServers?.hostNames ?? [];

      const summaryParts: string[] = [];
      if (domainAge !== null) {
        if (severity === 'medium') summaryParts.push(`RECENTLY REGISTERED (<30 days)`);
        summaryParts.push(`Age: ${domainAge} days`);
      }
      if (rec.registrarName) summaryParts.push(`Registrar: ${rec.registrarName}`);
      if (registrantOrg) summaryParts.push(`Org: ${registrantOrg}`);
      if (rec.expiresDate) summaryParts.push(`Expires: ${rec.expiresDate.split('T')[0]}`);

      return makeResult({
        status: 'ok',
        summary: `WHOIS: ${summaryParts.join(' | ') || 'Registration data found.'}`,
        severity,
        confidence: rec.createdDate ? 'high' : 'low',
        data: {
          registrar: rec.registrarName ?? null,
          registrationDate: rec.createdDate ?? null,
          expirationDate: rec.expiresDate ?? null,
          updatedDate: rec.updatedDate ?? null,
          domainAge,
          registrantOrg,
          country: registrant?.country ?? null,
          nameservers,
          status: rec.status ? [rec.status] : [],
        },
        rawAvailable: false,
        sourceUrl: `https://lookup.icann.org/lookup?name=${ioc.normalised}`,
        sourceReliability: 'authoritative' as const,
        keyFacts: [
          ...(domainAge !== null ? [{ label: 'Domain age', value: domainAge < 30 ? `${domainAge}d — newly registered` : `${domainAge} days` }] : []),
          ...(rec.registrarName ? [{ label: 'Registrar', value: rec.registrarName }] : []),
          ...(registrantOrg ? [{ label: 'Registrant org', value: registrantOrg }] : []),
          ...(rec.createdDate ? [{ label: 'Registered', value: rec.createdDate.split('T')[0] }] : []),
          ...(rec.expiresDate ? [{ label: 'Expires', value: rec.expiresDate.split('T')[0] }] : []),
          ...(nameservers.length > 0 ? [{ label: 'Nameservers', value: nameservers.slice(0, 2).join(', ') }] : []),
        ],
      });
    } else {
      // IP — WhoisXML returns network registration info in the same structure
      const summaryParts: string[] = [];
      const registrant = rec.registrant ?? rec.administrativeContact;
      const org = registrant?.organization ?? registrant?.name ?? null;
      const country = registrant?.country ?? null;
      if (org) summaryParts.push(`Org: ${org}`);
      if (country) summaryParts.push(`Country: ${country}`);

      return makeResult({
        status: 'ok',
        summary: `WHOIS: ${summaryParts.join(' | ') || 'IP registration data found.'}`,
        severity: 'unknown',
        confidence: org ? 'medium' : 'low',
        data: {
          registrantOrg: org,
          country,
        },
        rawAvailable: false,
        sourceUrl: `https://bgp.he.net/ip/${ioc.normalised}`,
        sourceReliability: 'authoritative' as const,
        keyFacts: [
          ...(org ? [{ label: 'Registrant org', value: org }] : []),
          ...(country ? [{ label: 'Country', value: country }] : []),
        ],
      });
    }
  } catch (err) {
    clearTimeout(timeout);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({
      status: 'error',
      summary: isTimeout ? 'WhoisXML API: request timed out.' : 'WhoisXML API: request failed.',
      errorMessage: err instanceof Error ? err.message : String(err),
    });
  }
}

// --- RDAP fallback ---

interface RdapEvent { eventAction: string; eventDate: string }
interface RdapEntity { roles: string[]; vcardArray?: unknown }
interface DomainRdap {
  events?: RdapEvent[];
  entities?: RdapEntity[];
  nameservers?: Array<{ ldhName?: string }>;
  status?: string[];
}
interface IpRdap {
  name?: string;
  startAddress?: string;
  endAddress?: string;
  ipVersion?: string;
  country?: string;
  entities?: RdapEntity[];
}

function getEventDate(events: RdapEvent[], action: string): string | undefined {
  return events.find(e => e.eventAction.toLowerCase() === action.toLowerCase())?.eventDate;
}

function extractFn(vcardArray: unknown): string {
  if (!Array.isArray(vcardArray) || vcardArray.length < 2) return '';
  const entries = vcardArray[1];
  if (!Array.isArray(entries)) return '';
  for (const entry of entries) {
    if (Array.isArray(entry) && entry[0] === 'fn' && entry.length >= 4) return String(entry[3] ?? '');
  }
  return '';
}

async function queryRdap(ioc: IocInput): Promise<EnrichmentResult> {
  const url = ioc.type === 'domain'
    ? `${RDAP_BASE}/domain/${ioc.normalised}`
    : `${RDAP_BASE}/ip/${ioc.normalised}`;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      headers: { 'Accept': 'application/rdap+json, application/json' },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (res.status === 404) {
      return makeResult({
        status: 'ok',
        summary: 'WHOIS/RDAP: No registration data found.',
        severity: 'unknown',
        confidence: 'low',
        data: { notFound: true },
      });
    }

    if (!res.ok) {
      return makeResult({
        status: 'error',
        summary: `WHOIS/RDAP returned HTTP ${res.status}.`,
        errorMessage: `HTTP ${res.status}`,
      });
    }

    if (ioc.type === 'domain') {
      const body = await res.json() as DomainRdap;
      const events = body.events ?? [];
      const registrationDate = getEventDate(events, 'registration');
      const expirationDate = getEventDate(events, 'expiration');
      const updatedDate = getEventDate(events, 'last changed');
      const domainAge = getDomainAge(registrationDate);
      const severity = domainSeverity(domainAge);

      const registrarEntity = body.entities?.find(e => e.roles.includes('registrar'));
      const registrar = registrarEntity ? extractFn(registrarEntity.vcardArray) : undefined;
      const nameservers = body.nameservers?.map(ns => ns.ldhName ?? '').filter(Boolean) ?? [];
      const status = body.status ?? [];

      const summaryParts: string[] = [];
      if (domainAge !== null) {
        if (severity === 'medium') summaryParts.push('RECENTLY REGISTERED (<30 days)');
        summaryParts.push(`Age: ${domainAge} days`);
      }
      if (registrar) summaryParts.push(`Registrar: ${registrar}`);
      if (expirationDate) summaryParts.push(`Expires: ${expirationDate.split('T')[0]}`);

      return makeResult({
        status: 'ok',
        summary: `WHOIS/RDAP: ${summaryParts.join(' | ') || 'Registration data found.'}`,
        severity,
        confidence: registrationDate ? 'high' : 'low',
        data: {
          registrar: registrar ?? null,
          registrationDate: registrationDate ?? null,
          expirationDate: expirationDate ?? null,
          updatedDate: updatedDate ?? null,
          domainAge,
          nameservers,
          status,
        },
        sourceUrl: `https://lookup.icann.org/lookup?name=${ioc.normalised}`,
        sourceReliability: 'authoritative' as const,
        keyFacts: [
          ...(domainAge !== null ? [{ label: 'Domain age', value: domainAge < 30 ? `${domainAge}d — newly registered` : `${domainAge} days` }] : []),
          ...(registrar ? [{ label: 'Registrar', value: registrar }] : []),
          ...(registrationDate ? [{ label: 'Registered', value: registrationDate.split('T')[0] }] : []),
          ...(expirationDate ? [{ label: 'Expires', value: expirationDate.split('T')[0] }] : []),
          ...(nameservers.length > 0 ? [{ label: 'Nameservers', value: nameservers.slice(0, 2).join(', ') }] : []),
        ],
      });
    } else {
      const body = await res.json() as IpRdap;
      const registrantEntity = body.entities?.find(e => e.roles.includes('registrant'));
      const registrantOrg = registrantEntity ? extractFn(registrantEntity.vcardArray) : undefined;

      const summaryParts: string[] = [];
      if (body.name) summaryParts.push(`Network: ${body.name}`);
      if (body.country) summaryParts.push(`Country: ${body.country}`);
      if (registrantOrg) summaryParts.push(`Org: ${registrantOrg}`);
      if (body.startAddress && body.endAddress) summaryParts.push(`Range: ${body.startAddress}–${body.endAddress}`);

      return makeResult({
        status: 'ok',
        summary: `WHOIS/RDAP: ${summaryParts.join(' | ') || 'IP registration data found.'}`,
        severity: 'unknown',
        confidence: 'medium',
        data: {
          networkName: body.name ?? null,
          networkRange: body.startAddress && body.endAddress ? `${body.startAddress}–${body.endAddress}` : null,
          country: body.country ?? null,
          registrantOrg: registrantOrg ?? null,
          ipVersion: body.ipVersion ?? null,
        },
        sourceUrl: `https://bgp.he.net/ip/${ioc.normalised}`,
        sourceReliability: 'authoritative' as const,
        keyFacts: [
          ...(body.name ? [{ label: 'Network', value: body.name }] : []),
          ...(registrantOrg ? [{ label: 'Registrant org', value: registrantOrg }] : []),
          ...(body.country ? [{ label: 'Country', value: body.country }] : []),
          ...(body.startAddress && body.endAddress ? [{ label: 'Range', value: `${body.startAddress}–${body.endAddress}` }] : []),
        ],
      });
    }
  } catch (err) {
    clearTimeout(timeout);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({
      status: 'error',
      summary: isTimeout ? 'WHOIS/RDAP: Request timed out.' : 'WHOIS/RDAP: Request failed.',
      errorMessage: err instanceof Error ? err.message : String(err),
    });
  }
}

// --- Entry point ---

export async function whois(ioc: IocInput, _options: EnrichOptions): Promise<EnrichmentResult> {
  if (ioc.type !== 'domain' && ioc.type !== 'ipv4' && ioc.type !== 'ipv6') {
    return makeResult({
      status: 'unsupported_ioc',
      summary: `WHOIS does not support IOC type: ${ioc.type}`,
    });
  }

  const apiKey = config.whoisxmlapi.apiKey;
  return apiKey ? queryWhoisXml(ioc, apiKey) : queryRdap(ioc);
}
