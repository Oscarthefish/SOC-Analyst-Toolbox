/** Pure parsing of raw email headers into authentication and routing facts. */

// ── Email header parser ──────────────────────────────────────────────────────

export interface ParsedEmailHeaders {
  sendingIp: string | null;
  fromAddress: string | null;
  fromDomain: string | null;
  toAddress: string | null;
  toAddresses: string[];
  returnPathDomain: string | null;
  envelopeDomain: string | null;
  replyToDomain: string | null;
  replyToAddress: string | null;
  deliveredTo: string | null;
  dkimDomain: string | null;
  subject: string | null;
  messageId: string | null;
  date: string | null;
  spf: string | null;
  dkim: string | null;
  dmarc: string | null;
  dmarcPolicy: string | null;
  spamScore: string | null;
  receivedSpf: string | null;
  authResults: string | null;
  hops: string[];
  suspiciousIndicators: string[];
}

// Unfold multi-line header values (RFC 2822 folding: CRLF + whitespace)
function unfoldHeaders(raw: string): string {
  return raw.replace(/\r?\n([ \t]+)/g, ' ');
}

// Extract the value after "HeaderName:" (case-insensitive)
function extractHeader(unfolded: string, name: string): string | null {
  const re = new RegExp(`^${name}:[ \t]*(.+)`, 'im');
  const m = unfolded.match(re);
  return m ? m[1].trim() : null;
}

// Extract ALL values for a repeated header
function extractAllHeaders(unfolded: string, name: string): string[] {
  const re = new RegExp(`^${name}:[ \t]*(.+)`, 'gim');
  const results: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(unfolded)) !== null) {
    results.push(m[1].trim());
  }
  return results;
}

// Pull first IPv4 that looks external from a Received header value
const PRIVATE_IP_RE = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1$|fe80:)/i;
const IP_RE = /\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/g;

function extractSendingIp(receivedHeaders: string[]): string | null {
  // Walk from the oldest (last) Received header towards the newest.
  // The topmost/newest Received is written by our own server. We want
  // the first external IP — the one injected from outside.
  for (let i = receivedHeaders.length - 1; i >= 0; i--) {
    const h = receivedHeaders[i]!;
    let m: RegExpExecArray | null;
    const re = new RegExp(IP_RE.source, 'g');
    while ((m = re.exec(h)) !== null) {
      const ip = m[1];
      if (!PRIVATE_IP_RE.test(ip!)) return ip!;
    }
  }
  return null;
}

// Extract domain from an email address string like "Display Name <user@example.com>"
function domainFromAddress(addr: string | null): string | null {
  if (!addr) return null;
  const angleMatch = addr.match(/<[^@]+@([^>]+)>/);
  if (angleMatch) return angleMatch[1].toLowerCase().trim();
  const atMatch = addr.match(/[^\s@]+@([^\s@>]+)/);
  return atMatch ? atMatch[1].toLowerCase().trim() : null;
}

// Extract bare email address (without display name)
function emailFromAddress(addr: string | null): string | null {
  if (!addr) return null;
  const angleMatch = addr.match(/<([^>@]+@[^>]+)>/);
  if (angleMatch) return angleMatch[1].trim().toLowerCase();
  const bareMatch = addr.match(/\b([^\s@,;]+@[^\s@,;]+)\b/);
  return bareMatch ? bareMatch[1].trim().toLowerCase() : null;
}

// Extract DMARC policy tag from Authentication-Results value
function extractDmarcPolicy(authResults: string | null): string | null {
  if (!authResults) return null;
  const m = authResults.match(/dmarc=\S+\s*\(policy=(\w+)\)/i);
  return m ? m[1].toLowerCase() : null;
}

// Normalise an auth result token to pass/fail/softfail/none/neutral/temperror/permerror
function normaliseAuthResult(raw: string | null, keyword: string): string | null {
  if (!raw) return null;
  const re = new RegExp(`${keyword}=([\\w]+)`, 'i');
  const m = raw.match(re);
  return m ? m[1].toLowerCase() : null;
}

/** True when `domain` equals `parent` or is a subdomain of it (label-aware, unlike endsWith). */
function sameOrSubdomain(domain: string, parent: string): boolean {
  return domain === parent || domain.endsWith(`.${parent}`);
}

export function parseEmailHeaders(raw: string): ParsedEmailHeaders {
  const unfolded = unfoldHeaders(raw);

  const receivedHeaders = extractAllHeaders(unfolded, 'Received');
  const sendingIp = extractSendingIp(receivedHeaders);

  const fromRaw = extractHeader(unfolded, 'From');
  const fromAddress = fromRaw;
  const fromDomain = domainFromAddress(fromRaw);

  const toRaw = extractHeader(unfolded, 'To');
  const toAddress = toRaw;
  const toAddresses = extractAllHeaders(unfolded, 'To');

  const returnPathRaw = extractHeader(unfolded, 'Return-Path');
  const returnPathDomain = domainFromAddress(returnPathRaw);

  const envelopeRaw = extractHeader(unfolded, 'Envelope-From') ?? extractHeader(unfolded, 'X-Envelope-From');
  const envelopeDomain = domainFromAddress(envelopeRaw);

  const replyToRaw = extractHeader(unfolded, 'Reply-To');
  const replyToDomain = domainFromAddress(replyToRaw);
  const replyToAddress = replyToRaw;

  // Actual delivery address — set by the receiving MTA, not the sender
  const deliveredTo =
    extractHeader(unfolded, 'Delivered-To') ??
    extractHeader(unfolded, 'X-Original-To') ??
    null;

  // Spam score — check Mimecast, SpamAssassin, and generic headers
  const spamScore =
    extractHeader(unfolded, 'X-Mimecast-Spam-Score') ??
    extractHeader(unfolded, 'X-Spam-Score') ??
    extractHeader(unfolded, 'X-SpamScore') ??
    null;

  // DKIM signing domain
  const dkimSig = extractHeader(unfolded, 'DKIM-Signature');
  const dkimDomainMatch = dkimSig?.match(/\bd=([^;\s]+)/i);
  const dkimDomain = dkimDomainMatch ? dkimDomainMatch[1].toLowerCase() : null;

  const subject = extractHeader(unfolded, 'Subject');
  const messageId = extractHeader(unfolded, 'Message-ID');
  const date = extractHeader(unfolded, 'Date');

  // Auth results: prefer Authentication-Results, fall back to ARC-Authentication-Results
  const authResults = extractAllHeaders(unfolded, 'Authentication-Results').join(' ') ||
    extractAllHeaders(unfolded, 'ARC-Authentication-Results').join(' ') || null;

  const receivedSpf = extractHeader(unfolded, 'Received-SPF');

  // Determine auth verdicts
  const spf = normaliseAuthResult(authResults, 'spf') ??
              normaliseAuthResult(receivedSpf, 'spf') ??
              (receivedSpf ? receivedSpf.split(/\s+/)[0]?.toLowerCase() ?? null : null);

  const dkim = normaliseAuthResult(authResults, 'dkim');
  const dmarc = normaliseAuthResult(authResults, 'dmarc');
  const dmarcPolicy = extractDmarcPolicy(authResults);

  // Collect hop summary
  const hops = receivedHeaders.slice(0, 5);

  // Suspicious indicator flags
  const suspiciousIndicators: string[] = [];

  // Self-sent: From == To (common in spam targeting the victim's own address)
  const fromEmail = emailFromAddress(fromRaw);
  const toEmail = emailFromAddress(toRaw);
  if (fromEmail && toEmail && fromEmail === toEmail) {
    suspiciousIndicators.push(`Self-sent: From and To are the same address (${fromEmail})`);
  }

  if (fromDomain && returnPathDomain && fromDomain !== returnPathDomain) {
    suspiciousIndicators.push(`From domain (${fromDomain}) differs from Return-Path domain (${returnPathDomain})`);
  }
  if (replyToDomain && fromDomain && replyToDomain !== fromDomain) {
    suspiciousIndicators.push(`Reply-To domain (${replyToDomain}) differs from From domain (${fromDomain})`);
  }
  if (dkimDomain && fromDomain && !sameOrSubdomain(fromDomain, dkimDomain) && !sameOrSubdomain(dkimDomain, fromDomain)) {
    suspiciousIndicators.push(`DKIM signing domain (${dkimDomain}) does not match From domain (${fromDomain})`);
  }
  if (spf && ['fail', 'softfail', 'permerror', 'temperror'].includes(spf)) {
    suspiciousIndicators.push(`SPF ${spf.toUpperCase()}`);
  }
  if (dkim && ['fail', 'permerror', 'temperror'].includes(dkim)) {
    suspiciousIndicators.push(`DKIM ${dkim.toUpperCase()}`);
  }
  if (dmarc && ['fail', 'permerror'].includes(dmarc)) {
    suspiciousIndicators.push(`DMARC ${dmarc.toUpperCase()}`);
  }
  // DMARC passes but policy=none means failures would not be quarantined/rejected
  if (dmarc === 'pass' && dmarcPolicy === 'none') {
    suspiciousIndicators.push('DMARC policy=none: domain owner receives reports but failures are not rejected or quarantined');
  }
  // High spam score
  const spamScoreNum = spamScore !== null ? parseFloat(spamScore) : NaN;
  if (!isNaN(spamScoreNum) && spamScoreNum >= 10) {
    suspiciousIndicators.push(`High spam score: ${spamScore}`);
  }

  return {
    sendingIp,
    fromAddress,
    fromDomain,
    toAddress,
    toAddresses,
    returnPathDomain,
    envelopeDomain,
    replyToDomain,
    replyToAddress,
    deliveredTo,
    dkimDomain,
    subject,
    messageId,
    date,
    spf,
    dkim,
    dmarc,
    dmarcPolicy,
    spamScore,
    receivedSpf,
    authResults,
    hops,
    suspiciousIndicators,
  };
}
