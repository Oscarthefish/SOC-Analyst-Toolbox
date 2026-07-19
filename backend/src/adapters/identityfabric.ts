import fetch from 'node-fetch';
import type { IocInput, EnrichmentResult, EnrichOptions } from '../types.js';

const PROVIDER_ID = 'identityfabric';
const PROVIDER_NAME = 'Identity Fabric';
const TIMEOUT_MS = 10_000;

// SAML metadata paths to probe
const SAML_PATHS = [
  '/saml/metadata',
  '/saml2/metadata',
  '/Shibboleth.sso/Metadata',
  '/federationmetadata/2007-06/federationmetadata.xml',
  '/auth/realms/master/protocol/saml/descriptor',
];

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

async function fetchJson(url: string, signal: AbortSignal): Promise<Record<string, unknown> | null> {
  try {
    const res = await fetch(url, {
      signal,
      headers: { Accept: 'application/json', 'User-Agent': 'SOC-Analyst-Toolbox/1.0' },
    });
    if (!res.ok) return null;
    return (await res.json()) as Record<string, unknown>;
  } catch {
    return null;
  }
}

async function fetchText(url: string, signal: AbortSignal): Promise<string | null> {
  try {
    const res = await fetch(url, {
      signal,
      headers: { 'User-Agent': 'SOC-Analyst-Toolbox/1.0' },
    });
    if (!res.ok) return null;
    return await res.text();
  } catch {
    return null;
  }
}

function extractTenantId(issuer: string): string | null {
  // Entra issuers: https://login.microsoftonline.com/{guid}/v2.0
  const match = issuer.match(
    /microsoftonline\.com\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i,
  );
  return match?.[1] ?? null;
}

function deriveOktaSlugs(domain: string): string[] {
  const stem = domain.split('.')[0] ?? domain;
  return [stem, `${stem}-admin`, `${stem}-preview`];
}

export async function identityfabric(
  ioc: IocInput,
  _options: EnrichOptions,
): Promise<EnrichmentResult> {
  if (ioc.type !== 'domain') {
    return makeResult({
      status: 'unsupported_ioc',
      summary: `Identity Fabric does not support IOC type: ${ioc.type} (supports: domain).`,
    });
  }

  const domain = ioc.normalised;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const discoveries: Array<{ idp: string; endpoint: string; tenantId?: string; detail?: string }> = [];

    // --- Microsoft Entra ---
    const entraUrl = `https://login.microsoftonline.com/${domain}/.well-known/openid-configuration`;
    const entraData = await fetchJson(entraUrl, controller.signal);
    if (entraData) {
      const issuer = typeof entraData.issuer === 'string' ? entraData.issuer : '';
      const tenantId = extractTenantId(issuer) ?? undefined;
      discoveries.push({ idp: 'Microsoft Entra (Azure AD)', endpoint: entraUrl, tenantId });
    }

    // --- Okta ---
    let oktaFound = false;
    for (const slug of deriveOktaSlugs(domain)) {
      if (oktaFound) break;
      const oktaUrl = `https://${slug}.okta.com/.well-known/openid-configuration`;
      const oktaData = await fetchJson(oktaUrl, controller.signal);
      if (oktaData && typeof oktaData.issuer === 'string') {
        discoveries.push({ idp: 'Okta', endpoint: oktaUrl, detail: `slug: ${slug}` });
        oktaFound = true;
      }
    }

    // --- Domain's own OIDC endpoint ---
    const oidcUrl = `https://${domain}/.well-known/openid-configuration`;
    const oidcData = await fetchJson(oidcUrl, controller.signal);
    if (oidcData && typeof oidcData.issuer === 'string') {
      const issuer = oidcData.issuer;
      // Skip if already found via Entra probe (same issuer)
      if (!discoveries.some(d => d.endpoint === entraUrl)) {
        const tenantId = extractTenantId(issuer) ?? undefined;
        discoveries.push({ idp: 'OIDC Provider', endpoint: oidcUrl, tenantId, detail: `issuer: ${issuer}` });
      }
    }

    // --- SAML metadata ---
    for (const path of SAML_PATHS) {
      const samlUrl = `https://${domain}${path}`;
      const body = await fetchText(samlUrl, controller.signal);
      if (body && body.includes('EntityDescriptor')) {
        const entityMatch = body.match(/entityID="([^"]+)"/);
        discoveries.push({
          idp: 'SAML IdP',
          endpoint: samlUrl,
          detail: entityMatch ? `entityID: ${entityMatch[1]}` : undefined,
        });
        break; // one SAML discovery per domain is enough
      }
    }

    clearTimeout(timeout);

    if (discoveries.length === 0) {
      return makeResult({
        status: 'ok',
        summary: `Identity Fabric: No IdP endpoints discovered for ${domain}.`,
        severity: 'unknown',
        confidence: 'medium',
        data: { discoveries: [] },
        sourceReliability: 'passive-infra',
        keyFacts: [{ label: 'IdP endpoints found', value: '0' }],
      });
    }

    const idpTypes = [...new Set(discoveries.map(d => d.idp))].join(', ');
    const tenantIds = discoveries.flatMap(d => (d.tenantId ? [d.tenantId] : []));

    return makeResult({
      status: 'ok',
      summary: `Identity Fabric: ${discoveries.length} IdP endpoint(s) found for ${domain} — ${idpTypes}.`,
      severity: 'low',
      confidence: 'high',
      data: {
        discoveries,
        tenantIds,
        idpTypes: [...new Set(discoveries.map(d => d.idp))],
      },
      sourceReliability: 'passive-infra',
      keyFacts: [
        { label: 'IdP endpoints', value: String(discoveries.length) },
        { label: 'Identity providers', value: idpTypes },
        ...(tenantIds.length > 0 ? [{ label: 'Tenant ID(s)', value: tenantIds.join(', ') }] : []),
        ...discoveries.map(d => ({
          label: d.idp,
          value: d.tenantId ?? d.detail ?? d.endpoint,
        })),
      ],
    });
  } catch {
    clearTimeout(timeout);
    return makeResult({
      status: 'error',
      summary: 'Identity Fabric probing timed out or failed.',
      errorMessage: 'Request timed out or network error',
    });
  }
}
