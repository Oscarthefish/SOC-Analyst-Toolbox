import type { IocInput, EnrichmentResult, EnrichOptions } from '../types.js';

const PROVIDER_ID = 'torproject';
const PROVIDER_NAME = 'Tor Project (Onionoo)';
const TIMEOUT_MS = 10_000;

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

interface OnionooRelay {
  nickname?: string;
  fingerprint?: string;
  or_addresses?: string[];   // e.g. ["1.2.3.4:9001"]
  exit_addresses?: string[]; // plain IPs used as exit
  flags?: string[];
  running?: boolean;
  country?: string;
  country_name?: string;
  bandwidth_rate?: number;
  contact?: string;
  first_seen?: string;
  last_seen?: string;
}

interface OnionooResponse {
  relays?: OnionooRelay[];
}

function stripPort(addr: string): string {
  // "1.2.3.4:9001" → "1.2.3.4", "[::1]:9001" → "::1"
  const v6match = addr.match(/^\[(.+)\]/);
  if (v6match) return v6match[1];
  return addr.split(':')[0] ?? addr;
}

export async function torproject(
  ioc: IocInput,
  _options: EnrichOptions,
): Promise<EnrichmentResult> {
  if (ioc.type !== 'ipv4' && ioc.type !== 'ipv6') {
    return makeResult({
      status: 'unsupported_ioc',
      summary: `Tor Project Onionoo does not support IOC type: ${ioc.type}.`,
    });
  }

  const ip = ioc.normalised;
  const url = `https://onionoo.torproject.org/details?search=${encodeURIComponent(ip)}`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { 'Accept': 'application/json' },
    });
    clearTimeout(timeout);

    if (!res.ok) {
      return makeResult({
        status: 'error',
        summary: `Tor Project Onionoo returned HTTP ${res.status}.`,
        errorMessage: `HTTP ${res.status}`,
      });
    }

    const body = (await res.json()) as OnionooResponse;
    const relays = body.relays ?? [];

    // Match by OR address or exit address
    const matched = relays.filter(r => {
      const orMatch  = (r.or_addresses ?? []).some(a => stripPort(a) === ip);
      const exitMatch = (r.exit_addresses ?? []).includes(ip);
      return orMatch || exitMatch;
    });

    if (matched.length === 0) {
      return makeResult({
        status: 'ok',
        summary: 'Tor Project: IP is not a known Tor relay or exit node.',
        severity: 'benign',
        confidence: 'high',
        data: { isTorNode: false },
        rawAvailable: false,
        sourceReliability: 'authoritative' as const,
        keyFacts: [{ label: 'Tor node', value: 'No' }],
      });
    }

    // Use the first (most relevant) match
    const relay = matched[0]!;
    const flags      = relay.flags ?? [];
    const isExit     = flags.includes('Exit');
    const isGuard    = flags.includes('Guard');
    const isRunning  = relay.running ?? false;
    const nickname   = relay.nickname ?? 'unknown';
    const fingerprint = relay.fingerprint ?? '';
    const country    = relay.country_name ?? relay.country ?? '';
    const firstSeen  = relay.first_seen ? relay.first_seen.split(' ')[0] : '';
    const lastSeen   = relay.last_seen  ? relay.last_seen.split(' ')[0]  : '';

    const roleLabel = [
      isExit  ? 'Exit node'  : null,
      isGuard ? 'Guard node' : null,
      !isExit && !isGuard ? 'Relay' : null,
    ].filter(Boolean).join(' + ');

    const statusLabel = isRunning ? 'currently active' : 'not currently active';

    let summary = `Tor Project: IP is a Tor ${roleLabel} (nickname: ${nickname}, ${statusLabel}).`;
    if (country)   summary += ` Country: ${country}.`;
    if (firstSeen) summary += ` First seen: ${firstSeen}.`;

    // Exit nodes that are currently active are the highest concern for SOC
    const severity = isExit && isRunning ? 'medium'
      : isRunning ? 'low'
      : 'low';

    return makeResult({
      status: 'ok',
      summary,
      severity,
      confidence: 'high',
      data: {
        isTorNode: true,
        isExitNode: isExit,
        isGuardNode: isGuard,
        isRunning,
        nickname,
        fingerprint,
        flags,
        country,
        firstSeen,
        lastSeen,
      },
      rawAvailable: true,
      sourceUrl: fingerprint
        ? `https://metrics.torproject.org/rs.html#details/${fingerprint}`
        : `https://metrics.torproject.org/rs.html#search/${ip}`,
      sourceReliability: 'authoritative' as const,
      keyFacts: [
        { label: 'Tor node', value: 'Yes' },
        { label: 'Role', value: roleLabel },
        { label: 'Status', value: statusLabel },
        ...(nickname !== 'unknown' ? [{ label: 'Nickname', value: nickname }] : []),
        ...(country ? [{ label: 'Country', value: country }] : []),
        ...(firstSeen ? [{ label: 'First seen', value: firstSeen }] : []),
      ],
    });
  } catch (err) {
    clearTimeout(timeout);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({
      status: 'error',
      summary: isTimeout ? 'Tor Project Onionoo request timed out.' : 'Tor Project Onionoo request failed.',
      errorMessage: err instanceof Error ? err.message : String(err),
    });
  }
}
