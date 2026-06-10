import type { DetectedIoc } from '../types/ioc';
import { getBestSearchValue } from './normalizeIoc';

export interface TemplateVars {
  value: string;
  encodedValue: string;
  ip: string;
  encodedIp: string;
  domain: string;
  encodedDomain: string;
  url: string;
  encodedUrl: string;
  hash: string;
  email: string;
  encodedEmail: string;
  asn: string;
  cidr: string;
  encodedQuery: string;
}

export function buildTemplateVars(ioc: DetectedIoc): TemplateVars {
  const n = ioc.normalised;
  const best = getBestSearchValue(ioc);

  let ip = '';
  let domain = '';
  let url = '';
  let hash = '';
  let email = '';
  let asn = '';
  let cidr = '';

  if (ioc.type === 'ipv4' || ioc.type === 'ipv6') {
    ip = n;
  } else if (ioc.type === 'domain') {
    domain = n;
  } else if (ioc.type === 'url') {
    url = n;
    domain = ioc.urlExtract?.domain ?? '';
    ip = ''; // IP could be extracted if needed
  } else if (ioc.type === 'md5' || ioc.type === 'sha1' || ioc.type === 'sha256') {
    hash = n;
  } else if (ioc.type === 'email') {
    email = n;
  } else if (ioc.type === 'asn') {
    asn = n;
  } else if (ioc.type === 'cidr') {
    cidr = n;
    ip = n.split('/')[0];
  }

  return {
    value: n,
    encodedValue: encodeURIComponent(n),
    ip,
    encodedIp: encodeURIComponent(ip),
    domain,
    encodedDomain: encodeURIComponent(domain),
    url,
    encodedUrl: ioc.urlExtract?.encodedUrl ?? encodeURIComponent(url),
    hash,
    email,
    encodedEmail: encodeURIComponent(email),
    asn,
    cidr,
    encodedQuery: encodeURIComponent(best),
  };
}

export function applyTemplate(template: string, vars: TemplateVars): string {
  return template
    .replace(/\{\{value\}\}/g, vars.value)
    .replace(/\{\{encodedValue\}\}/g, vars.encodedValue)
    .replace(/\{\{ip\}\}/g, vars.ip)
    .replace(/\{\{encodedIp\}\}/g, vars.encodedIp)
    .replace(/\{\{domain\}\}/g, vars.domain)
    .replace(/\{\{encodedDomain\}\}/g, vars.encodedDomain)
    .replace(/\{\{url\}\}/g, vars.url)
    .replace(/\{\{encodedUrl\}\}/g, vars.encodedUrl)
    .replace(/\{\{hash\}\}/g, vars.hash)
    .replace(/\{\{email\}\}/g, vars.email)
    .replace(/\{\{encodedEmail\}\}/g, vars.encodedEmail)
    .replace(/\{\{asn\}\}/g, vars.asn)
    .replace(/\{\{cidr\}\}/g, vars.cidr)
    .replace(/\{\{encodedQuery\}\}/g, vars.encodedQuery);
}

/**
 * Returns false if the generated URL still has unfilled {{...}} placeholders
 * that would indicate the tool doesn't support this IOC type.
 */
export function isTemplateValid(generated: string): boolean {
  return !generated.includes('{{') || !generated.includes('}}');
}
