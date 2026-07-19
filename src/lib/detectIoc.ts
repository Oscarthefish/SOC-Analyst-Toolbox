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

// Known credential patterns — ordered from most specific to least
const CREDENTIAL_PATTERNS: Array<{ name: string; re: RegExp }> = [
  { name: 'AWS Access Key',      re: /^AKIA[0-9A-Z]{16}$/ },
  { name: 'AWS Session Key',     re: /^ASIA[0-9A-Z]{16}$/ },
  { name: 'Anthropic API Key',   re: /^sk-ant-(?:api03|admin01)-/ },
  { name: 'OpenAI API Key',      re: /^sk-proj-|^sk-[A-Za-z0-9]{20}T3BlbkFJ/ },
  { name: 'GitHub PAT (classic)',re: /^ghp_[A-Za-z0-9]{36}$/ },
  { name: 'GitHub PAT (fine-grained)', re: /^github_pat_[A-Za-z0-9_]{82}$/ },
  { name: 'GitHub App Token',    re: /^ghs_[A-Za-z0-9]{36}$/ },
  { name: 'GitLab PAT',         re: /^glpat-[A-Za-z0-9\-_]{20}$/ },
  { name: 'Slack Bot Token',     re: /^xoxb-\d{11,12}-\d{11,12}-[A-Za-z0-9]{24}$/ },
  { name: 'Slack User Token',    re: /^xoxp-\d{11,12}-\d{11,12}-\d{11,12}-[a-f0-9]{32}$/ },
  { name: 'npm Access Token',    re: /^npm_[A-Za-z0-9]{36}$/ },
  { name: 'HuggingFace Token',   re: /^hf_[A-Za-z0-9]{37}$/ },
  { name: 'Stripe Secret Key',   re: /^sk_live_[A-Za-z0-9]{24,}$/ },
  { name: 'Postman API Key',     re: /^PMAK-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{24}$/ },
  { name: 'DigitalOcean Token',  re: /^dop_v1_[A-Za-z0-9]{64}$/ },
];

function detectCredential(value: string): string | null {
  for (const { name, re } of CREDENTIAL_PATTERNS) {
    if (re.test(value)) return name;
  }
  return null;
}
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

export function normalizeIocInput(raw: string): string {
  return raw
    .replace(/(?:\u200B|\u200C|\u200D|\uFEFF|\u00AD)/g, '') // zero-width / soft-hyphen chars
    .replace(/\[\.\]/g, '.')   // [.] → .
    .replace(/\(\.\)/g, '.')   // (.) → .
    .replace(/^hxxps?:\/\//i, m => m.replace(/xx/i, 'tt')) // hxxp → http
    .trim();
}

export function detectIoc(input: string): DetectedIoc {
  const trimmed = normalizeIocInput(input.trim());
  let type: IocType = 'unknown';
  let confidence: DetectedIoc['confidence'] = 'low';
  let normalised: string;
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
  // Credential / secret token
  else if (detectCredential(trimmed)) {
    type = 'secret';
    confidence = 'high';
    normalised = trimmed;
  }
  // Domain (try stripping protocol/path first)
  else {
    // Try normalising sloppy domain inputs
    const candidate = trimmed
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

  const credentialType = type === 'secret' ? (detectCredential(trimmed) ?? undefined) : undefined;
  const isCredential = type === 'secret';
  const credentialWarning = isCredential
    ? `This looks like a ${credentialType ?? 'credential'}. Do NOT submit to external enrichment providers — it may still be active. Use the built-in Credential Validator (providers: credvalidate) for read-only validation only.`
    : undefined;

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
    isCredential,
    credentialType,
    credentialWarning,
  };
}
