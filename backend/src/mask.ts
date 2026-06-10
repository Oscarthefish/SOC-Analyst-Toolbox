import type { IocInput } from './types.js';

export function maskApiKey(key: string): string {
  if (!key || key.length < 8) return '***';
  return key.slice(0, 4) + '***' + key.slice(-2);
}

export function maskSensitiveUrl(url: string): string {
  try {
    const parsed = new URL(url);
    const base = `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
    const params = parsed.searchParams;
    if (params.size === 0) return base;

    const redacted = new URLSearchParams();
    for (const key of params.keys()) {
      redacted.set(key, '[redacted]');
    }
    return `${base}?${redacted.toString()}`;
  } catch {
    // Not a valid URL — return as-is with query portion stripped
    const qIdx = url.indexOf('?');
    return qIdx >= 0 ? url.slice(0, qIdx) + '?[redacted]' : url;
  }
}

export function maskEmail(email: string): string {
  const atIdx = email.indexOf('@');
  if (atIdx < 0) return '***';
  const local = email.slice(0, atIdx);
  const domain = email.slice(atIdx);
  if (local.length <= 1) return `*${domain}`;
  return `${local[0]}***${domain}`;
}

export function safeLogIoc(ioc: IocInput): string {
  if (ioc.type === 'url') {
    return maskSensitiveUrl(ioc.normalised);
  }
  return ioc.normalised;
}
