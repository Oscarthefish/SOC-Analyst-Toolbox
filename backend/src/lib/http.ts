/**
 * Outbound HTTP defaults, installed once at startup.
 *
 *  - User-Agent: Node's built-in fetch sends `User-Agent: node`, which some providers
 *    reject (rdap.org returns 403). Requests without one get a descriptive default.
 *  - Deadline: adapters clear their own timeout as soon as response headers arrive, so a
 *    provider that stalls mid-body could hang a lookup indefinitely. Every request to a
 *    remote host also gets a hard deadline covering the whole exchange, body included.
 *    Local services (Ollama) are exempt: they manage their own, longer timeouts.
 */
export const USER_AGENT = 'SOC-Analyst-Toolbox/1.0';
export const DEFAULT_DEADLINE_MS = 30_000;

export function withDefaultUserAgent(init?: RequestInit): RequestInit {
  const headers = new Headers(init?.headers);
  if (!headers.has('User-Agent')) headers.set('User-Agent', USER_AGENT);
  return { ...init, headers };
}

function isLocal(input: Parameters<typeof fetch>[0]): boolean {
  const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
  try {
    const host = new URL(url).hostname;
    return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]';
  } catch {
    return false;
  }
}

/** Combine the caller's signal (if any) with a deadline for the whole request. */
export function withDeadline(init: RequestInit, ms: number): RequestInit {
  const deadline = AbortSignal.timeout(ms);
  return { ...init, signal: init.signal ? AbortSignal.any([init.signal, deadline]) : deadline };
}

let installed = false;

export function installFetchDefaults({ deadlineMs = DEFAULT_DEADLINE_MS } = {}): void {
  if (installed) return;
  installed = true;
  const original = globalThis.fetch;
  globalThis.fetch = (input, init) => {
    const withUa = withDefaultUserAgent(init);
    return original(input, isLocal(input) ? withUa : withDeadline(withUa, deadlineMs));
  };
}
