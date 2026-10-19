/**
 * Outbound HTTP defaults, installed once at startup.
 *
 * Node's built-in fetch sends `User-Agent: node`, which some providers reject
 * (rdap.org returns 403). Every request without an explicit User-Agent gets a
 * descriptive one instead.
 */
export const USER_AGENT = 'SOC-Analyst-Toolbox/1.0';

export function withDefaultUserAgent(init?: RequestInit): RequestInit {
  const headers = new Headers(init?.headers);
  if (!headers.has('User-Agent')) headers.set('User-Agent', USER_AGENT);
  return { ...init, headers };
}

let installed = false;

export function installFetchDefaults(): void {
  if (installed) return;
  installed = true;
  const original = globalThis.fetch;
  globalThis.fetch = (input, init) => original(input, withDefaultUserAgent(init));
}
