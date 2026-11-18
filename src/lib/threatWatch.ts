import type { DetectedIoc } from '../types/ioc';

/**
 * Links into a Threat Watch instance (the backend's THREATWATCH_URL).
 * A CVE opens its vulnerability page; other indicators open a search of collected reporting.
 * URLs are searched by host name only: full URLs rarely appear in reporting and can carry tokens.
 */
export function threatWatchLink(base: string, ioc: DetectedIoc): string | null {
  if (!base || ioc.isEmailHeader) return null;
  switch (ioc.type) {
    case 'cve':
      return `${base}/vuln/${encodeURIComponent(ioc.normalised.toUpperCase())}`;
    case 'url': {
      const domain = ioc.urlExtract?.domain;
      return domain ? `${base}/search?q=${encodeURIComponent(domain)}` : null;
    }
    case 'secret':
    case 'unknown':
      return null;
    default:
      return `${base}/search?q=${encodeURIComponent(ioc.normalised)}`;
  }
}

export function openExternal(url: string): void {
  window.open(url, '_blank', 'noopener,noreferrer');
}
