/**
 * Defang/refang utilities for safe sharing of IOCs in reports and tickets.
 */

// Defang an IPv4 address: 1.2.3.4 -> 1[.]2[.]3[.]4
export function defangIp(ip: string): string {
  return ip.replace(/\./g, '[.]');
}

// Defang a domain: example.com -> example[.]com
export function defangDomain(domain: string): string {
  return domain.replace(/\./g, '[.]');
}

// Defang a URL: https://example.com/path -> hxxps://example[.]com/path
export function defangUrl(url: string): string {
  return url
    .replace(/^https/i, 'hxxps')
    .replace(/^http(?!s)/i, 'hxxp')
    .replace(/\./g, '[.]')
    .replace(/\[\.](com|net|org|io|co|uk|gov|edu|mil|int|info|biz|me|tv|us|ca|de|fr|au|jp|cn|ru)\b/gi, (match) => match);
}

// A smarter defang for URLs that only replaces dots in hostname, not scheme
export function defangUrlSmart(url: string): string {
  try {
    const parsed = new URL(url);
    const defangedScheme = parsed.protocol.replace('https:', 'hxxps:').replace('http:', 'hxxp:');
    const defangedHost = parsed.hostname.replace(/\./g, '[.]');
    const rest = parsed.pathname + parsed.search + parsed.hash;
    return `${defangedScheme}//${defangedHost}${rest}`;
  } catch {
    // Fallback: crude replacement
    return url
      .replace(/^https/i, 'hxxps')
      .replace(/^http(?!s)/i, 'hxxp')
      .replace(/:\/\/([^/]+)/, (_match, host: string) => `://${host.replace(/\./g, '[.]')}`);
  }
}

// Refang an IP: 1[.]2[.]3[.]4 -> 1.2.3.4
export function refangIp(ip: string): string {
  return ip.replace(/\[\.\]/g, '.');
}

// Refang a domain: example[.]com -> example.com
export function refangDomain(domain: string): string {
  return domain.replace(/\[\.\]/g, '.');
}

// Refang a URL: hxxps://example[.]com/path -> https://example.com/path
export function refangUrl(url: string): string {
  return url
    .replace(/^hxxps/i, 'https')
    .replace(/^hxxp(?!s)/i, 'http')
    .replace(/\[\.\]/g, '.');
}

export type DefangType = 'ipv4' | 'ipv6' | 'domain' | 'url' | 'email' | 'cidr' | 'other';

export interface DefangResult {
  original: string;
  type: DefangType;
  defanged: string;
  refanged: string;
}

// Detect type and produce both defanged and refanged versions
export function processDefang(input: string): DefangResult {
  const trimmed = input.trim();

  // Detect if already defanged (contains [.] or starts with hxxp)
  const isAlreadyDefanged = trimmed.includes('[.]') || /^hxxp/i.test(trimmed);

  if (/^hxxps?:\/\//i.test(trimmed)) {
    const refanged = refangUrl(trimmed);
    return { original: trimmed, type: 'url', defanged: defangUrlSmart(refanged), refanged };
  }

  if (/^https?:\/\//i.test(trimmed)) {
    return { original: trimmed, type: 'url', defanged: defangUrlSmart(trimmed), refanged: trimmed };
  }

  // CIDR (e.g. 10.0.0.0/8 or 10[.]0[.]0[.]0/8)
  // eslint-disable-next-line no-useless-escape
  if (/^[\d.\[\]]+\/\d{1,2}$/.test(trimmed)) {
    const slashIdx = trimmed.lastIndexOf('/');
    const ipPart = trimmed.slice(0, slashIdx);
    const prefix = trimmed.slice(slashIdx); // includes the /
    const refangedIp = refangIp(ipPart);
    const refanged = refangedIp + prefix;
    const defanged = defangIp(refangedIp) + prefix;
    return { original: trimmed, type: 'cidr', defanged, refanged };
  }

  // IPv4 (plain or defanged)
  const ipCandidate = isAlreadyDefanged ? refangIp(trimmed) : trimmed;
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ipCandidate)) {
    return { original: trimmed, type: 'ipv4', defanged: defangIp(ipCandidate), refanged: ipCandidate };
  }

  // Email — detect before domain
  const emailCandidate = isAlreadyDefanged ? trimmed.replace(/\[\.\]/g, '.') : trimmed;
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailCandidate)) {
    const defanged = emailCandidate.replace(/\./g, '[.]').replace('@', '[@]');
    const refanged = emailCandidate;
    return { original: trimmed, type: 'email', defanged, refanged };
  }

  // Domain
  const domainCandidate = isAlreadyDefanged ? refangDomain(trimmed) : trimmed;
  if (/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(domainCandidate)) {
    return { original: trimmed, type: 'domain', defanged: defangDomain(domainCandidate), refanged: domainCandidate };
  }

  // IPv6
  if (/^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(trimmed)) {
    return { original: trimmed, type: 'ipv6', defanged: trimmed, refanged: trimmed };
  }

  return { original: trimmed, type: 'other', defanged: trimmed, refanged: trimmed };
}
