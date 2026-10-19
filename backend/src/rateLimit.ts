/**
 * Per-provider rate limiting.
 *
 * Two mechanisms:
 *  - Proactive: a sliding one-minute window per provider, so we stay under documented
 *    free-tier quotas instead of discovering them via HTTP 429.
 *  - Reactive: after a provider returns 429, adapters call markRateLimited() and the
 *    provider is paused for 60 s.
 *
 * Override or add a limit with RATE_LIMIT_<PROVIDER>=<requests per minute>,
 * e.g. RATE_LIMIT_VIRUSTOTAL=500 for a premium key. 0 disables the proactive limit.
 */

const WINDOW_MS = 60_000;
const PENALTY_MS = 60_000;
/** Wait for a free slot if one opens within this long; otherwise report rate_limited. */
export const MAX_WAIT_MS = 15_000;

/** Free-tier limits (requests per minute) for providers that document them. */
const DEFAULT_LIMITS: Record<string, number> = {
  virustotal: 4,  // public API: 4 lookups/min
  ipapi: 45,      // ip-api.com free endpoint
  shodan: 60,     // 1 request/second
  hibp: 10,       // lowest paid tier
};

interface Bucket {
  timestamps: number[];
  rateLimitedUntil: number;
}

const buckets = new Map<string, Bucket>();

function bucketFor(providerId: string): Bucket {
  let b = buckets.get(providerId);
  if (!b) {
    b = { timestamps: [], rateLimitedUntil: 0 };
    buckets.set(providerId, b);
  }
  return b;
}

export function limitFor(providerId: string): number {
  const env = process.env[`RATE_LIMIT_${providerId.toUpperCase()}`];
  if (env !== undefined && env !== '') {
    const n = parseInt(env, 10);
    if (!isNaN(n) && n >= 0) return n;
  }
  return DEFAULT_LIMITS[providerId] ?? 0;
}

/** Milliseconds until this provider may be called, or 0 if it may be called now. */
function waitTime(providerId: string, now: number): number {
  const b = bucketFor(providerId);
  if (b.rateLimitedUntil > now) return b.rateLimitedUntil - now;

  const limit = limitFor(providerId);
  if (limit === 0) return 0;
  b.timestamps = b.timestamps.filter(t => now - t < WINDOW_MS);
  if (b.timestamps.length < limit) return 0;
  return b.timestamps[0]! + WINDOW_MS - now;
}

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

/**
 * Reserve a request slot. Resolves to 0 once the caller may proceed, or to the
 * number of milliseconds to wait if no slot opens within MAX_WAIT_MS.
 */
export async function acquire(providerId: string, maxWaitMs = MAX_WAIT_MS): Promise<number> {
  const deadline = Date.now() + maxWaitMs;
  for (;;) {
    const now = Date.now();
    const wait = waitTime(providerId, now);
    if (wait === 0) {
      bucketFor(providerId).timestamps.push(now);
      return 0;
    }
    if (now + wait > deadline) return wait;
    await sleep(wait);
  }
}

/** Pause a provider for 60 s after it returned HTTP 429. */
export function markRateLimited(providerId: string): void {
  bucketFor(providerId).rateLimitedUntil = Date.now() + PENALTY_MS;
}

/** True if the provider is currently paused or at its limit (no waiting). */
export function isRateLimited(providerId: string): boolean {
  return waitTime(providerId, Date.now()) > 0;
}

/** Requests made in the current window. */
export function getRequestCount(providerId: string): number {
  const now = Date.now();
  return bucketFor(providerId).timestamps.filter(t => now - t < WINDOW_MS).length;
}

/** For tests. */
export function resetRateLimits(): void {
  buckets.clear();
}
