interface ProviderBucket {
  count: number;
  windowStart: number;
  rateLimitedUntil: number | null;
}

const buckets = new Map<string, ProviderBucket>();
const WINDOW_MS = 60_000; // 1 minute

function getBucket(providerId: string): ProviderBucket {
  let bucket = buckets.get(providerId);
  if (!bucket) {
    bucket = { count: 0, windowStart: Date.now(), rateLimitedUntil: null };
    buckets.set(providerId, bucket);
  }

  // Reset window if expired
  if (Date.now() - bucket.windowStart > WINDOW_MS) {
    bucket.count = 0;
    bucket.windowStart = Date.now();
  }

  return bucket;
}

/**
 * Returns true if the provider is currently rate-limited.
 */
export function isRateLimited(providerId: string): boolean {
  const bucket = getBucket(providerId);
  if (bucket.rateLimitedUntil !== null && Date.now() < bucket.rateLimitedUntil) {
    return true;
  }
  if (bucket.rateLimitedUntil !== null && Date.now() >= bucket.rateLimitedUntil) {
    // Clear the rate-limit penalty
    bucket.rateLimitedUntil = null;
  }
  return false;
}

/**
 * Record a successful request for the provider.
 */
export function recordRequest(providerId: string): void {
  const bucket = getBucket(providerId);
  bucket.count += 1;
}

/**
 * Mark a provider as rate-limited for 60 seconds.
 */
export function markRateLimited(providerId: string): void {
  const bucket = getBucket(providerId);
  bucket.rateLimitedUntil = Date.now() + 60_000;
}

/**
 * Get the request count for the current window.
 */
export function getRequestCount(providerId: string): number {
  return getBucket(providerId).count;
}
