import type { DetectedIoc, IocType, UrlExtract } from '../types/ioc';
import { SENSITIVE_URL_TERMS } from './sensitive';

// Email header block detection: look for typical MIME/SMTP field names at line starts
const EMAIL_HEADER_FIELDS = /^(Received|Delivered-To|Return-Path|Message-ID|MIME-Version|Content-Type|Subject|From|To|Date|Reply-To|X-[A-Za-z]|ARC-|Authentication-Results|DKIM-Signature|Received-SPF):/im;

function looksLikeEmailHeader(text: string): boolean {
  const lines = text.split('\n').slice(0, 20);
  const matches = lines.filter(l => EMAIL_HEADER_FIELDS.test(l));
  return matches.length >= 2;
}

const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV4_CIDR_RE = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
const IPV6_RE = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
const MD5_RE = /^[0-9a-fA-F]{32}$/;
const SHA1_RE = /^[0-9a-fA-F]{40}$/;
const SHA256_RE = /^[0-9a-fA-F]{64}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ASN_RE = /^AS\d+$/i;
const DOMAIN_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const URL_RE = /^https?:\/\//i;

function extractUrl(raw: string): UrlExtract {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(raw);
  } catch {
    parsedUrl = new URL('http://' + raw);
  }

  const scheme = parsedUrl.protocol.replace(':', '');
  const hostname = parsedUrl.hostname;
  const path = parsedUrl.pathname;
  const query = parsedUrl.search;
  const queryParamNames = Array.from(parsedUrl.searchParams.keys());

  const combined = (path + ' ' + query).toLowerCase();
  const sensitiveTerms = SENSITIVE_URL_TERMS.filter(t => combined.includes(t));
  const isSensitive = sensitiveTerms.length > 0;

  const domain = hostname.replace(/^www\./, '');

  return {
    fullUrl: raw,
    scheme,
    hostname,
    domain,
    path,
    query,
    queryParamNames,
    encodedUrl: encodeURIComponent(raw),
    encodedHostname: encodeURIComponent(hostname),
    isSensitive,
    sensitiveTerms,
  };
}

export function detectIoc(input: string): DetectedIoc {
  const trimmed = input.trim();
  let type: IocType = 'unknown';
  let confidence: DetectedIoc['confidence'] = 'low';
  let normalised = trimmed;
  let urlExtract: UrlExtract | undefined;

  if (!trimmed) {
    return { original: input, trimmed, type: 'unknown', confidence: 'low', normalised: '' };
  }

  // CVE
  if (CVE_RE.test(trimmed)) {
    type = 'cve';
    confidence = 'high';
    normalised = trimmed.toUpperCase();
  }
  // URL
  else if (URL_RE.test(trimmed)) {
    type = 'url';
    confidence = 'high';
    urlExtract = extractUrl(trimmed);
    normalised = trimmed;
  }
  // CIDR
  else if (IPV4_CIDR_RE.test(trimmed)) {
    type = 'cidr';
    confidence = 'high';
    normalised = trimmed;
  }
  // IPv4
  else if (IPV4_RE.test(trimmed)) {
    const parts = trimmed.split('.').map(Number);
    if (parts.every(p => p >= 0 && p <= 255)) {
      type = 'ipv4';
      confidence = 'high';
    }
    normalised = trimmed;
  }
  // IPv6
  else if (IPV6_RE.test(trimmed)) {
    type = 'ipv6';
    confidence = 'high';
    normalised = trimmed.toLowerCase();
  }
  // ASN
  else if (ASN_RE.test(trimmed)) {
    type = 'asn';
    confidence = 'high';
    normalised = trimmed.toUpperCase();
  }
  // SHA256
  else if (SHA256_RE.test(trimmed)) {
    type = 'sha256';
    confidence = 'high';
    normalised = trimmed.toLowerCase();
  }
  // SHA1
  else if (SHA1_RE.test(trimmed)) {
    type = 'sha1';
    confidence = 'high';
    normalised = trimmed.toLowerCase();
  }
  // MD5
  else if (MD5_RE.test(trimmed)) {
    type = 'md5';
    confidence = 'high';
    normalised = trimmed.toLowerCase();
  }
  // Email
  else if (EMAIL_RE.test(trimmed)) {
    type = 'email';
    confidence = 'high';
    normalised = trimmed.toLowerCase();
  }
  // Domain (try stripping protocol/path first)
  else {
    // Try normalising sloppy domain inputs
    let candidate = trimmed
      .replace(/^https?:\/\//i, '')
      .replace(/\/.*$/, '')
      .replace(/\?.*$/, '')
      .toLowerCase()
      .trim();

    if (candidate !== trimmed) {
      // The user pasted something with a protocol or path but no http:// (would have been caught above)
      // treat as domain after normalisation
    }

    if (DOMAIN_RE.test(candidate)) {
      type = 'domain';
      confidence = candidate !== trimmed ? 'medium' : 'high';
      normalised = candidate;
    } else {
      type = 'unknown';
      confidence = 'low';
      normalised = trimmed;
    }
  }

  const isSensitiveUrl = type === 'url' && (urlExtract?.isSensitive ?? false);
  const sensitiveUrlWarning = isSensitiveUrl
    ? 'This URL may contain sensitive tokens or user identifiers. Avoid submitting it to public tools. Prefer private tooling, search-only pivots, or internal sandboxing.'
    : undefined;

  const isEmailHeader = type === 'unknown' && looksLikeEmailHeader(trimmed);

  return {
    original: input,
    trimmed,
    type,
    confidence,
    normalised,
    urlExtract,
    isSensitiveUrl,
    sensitiveUrlWarning,
    isEmailHeader,
  };
}
