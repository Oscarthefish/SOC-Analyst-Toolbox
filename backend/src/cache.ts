import { createHash } from 'crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, renameSync } from 'fs';
import { writeFile, rename } from 'fs/promises';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { EnrichmentResult } from './types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const CACHE_DIR = process.env.CACHE_DIR ?? join(__dirname, '../../.cache');
const CACHE_FILE = join(CACHE_DIR, 'enrichment-cache.json');

/** Writes are coalesced: many sets within this window produce one disk write. */
const FLUSH_DELAY_MS = 1_000;
/** Oldest-expiring entries are evicted beyond this many. */
const MAX_ENTRIES = 5_000;
const PRUNE_INTERVAL_MS = 10 * 60_000;

interface CacheEntry {
  result: EnrichmentResult;
  expiresAt: string;
}

type CacheStore = Record<string, CacheEntry>;

function loadFromDisk(): CacheStore {
  if (!existsSync(CACHE_FILE)) return {};
  try {
    return JSON.parse(readFileSync(CACHE_FILE, 'utf-8')) as CacheStore;
  } catch {
    // Corrupt file — start fresh
    return {};
  }
}

let store: CacheStore = loadFromDisk();
let flushTimer: ReturnType<typeof setTimeout> | null = null;
let flushing: Promise<void> | null = null;
let dirty = false;

async function flush(): Promise<void> {
  flushTimer = null;
  if (!dirty) return;
  dirty = false;
  try {
    mkdirSync(CACHE_DIR, { recursive: true });
    const tmp = `${CACHE_FILE}.tmp`;
    // Compact JSON and an atomic rename: a crash mid-write never corrupts the cache
    await writeFile(tmp, JSON.stringify(store), 'utf-8');
    await rename(tmp, CACHE_FILE);
  } catch (err) {
    console.error('[cache] Failed to write cache to disk:', err);
  }
}

function scheduleFlush(): void {
  dirty = true;
  if (flushTimer) return;
  flushTimer = setTimeout(() => {
    flushing = flush().finally(() => { flushing = null; });
  }, FLUSH_DELAY_MS);
  flushTimer.unref();
}

/** Write pending changes synchronously (used on shutdown). */
export function flushSync(): void {
  if (flushTimer) { clearTimeout(flushTimer); flushTimer = null; }
  if (!dirty) return;
  dirty = false;
  try {
    mkdirSync(CACHE_DIR, { recursive: true });
    writeFileSync(`${CACHE_FILE}.tmp`, JSON.stringify(store), 'utf-8');
    renameSync(`${CACHE_FILE}.tmp`, CACHE_FILE);
  } catch (err) {
    console.error('[cache] Failed to flush cache on shutdown:', err);
  }
}

/** Await any scheduled or in-flight write (for tests). */
export async function flushNow(): Promise<void> {
  if (flushTimer) { clearTimeout(flushTimer); await flush(); }
  if (flushing) await flushing;
}

/**
 * Build a cache key. URLs (may carry tokens) and secrets are hashed so raw values
 * are never written to disk.
 */
export function buildCacheKey(
  providerId: string,
  iocType: string,
  normalisedIoc: string,
  isSensitiveUrl = false,
): string {
  const iocPart =
    // Never write raw URLs (may carry tokens) or credentials to disk
    isSensitiveUrl || iocType === 'url' || iocType === 'secret'
      ? createHash('sha256').update(normalisedIoc).digest('hex').slice(0, 16)
      : normalisedIoc;
  return `${providerId}:${iocType}:${iocPart}`;
}

export function get(key: string): EnrichmentResult | null {
  const entry = store[key];
  if (!entry) return null;
  if (new Date(entry.expiresAt) < new Date()) {
    delete store[key];
    scheduleFlush();
    return null;
  }
  return { ...entry.result, fromCache: true };
}

export function set(key: string, result: EnrichmentResult, ttlMinutes: number): void {
  const expiresAt = new Date(Date.now() + ttlMinutes * 60_000).toISOString();
  store[key] = { result, expiresAt };
  evictOverflow();
  scheduleFlush();
}

export function clear(): void {
  store = {};
  scheduleFlush();
}

export function size(): number {
  return Object.keys(store).length;
}

/** Remove expired entries. Returns how many were removed. */
export function prune(): number {
  const now = new Date();
  let removed = 0;
  for (const key of Object.keys(store)) {
    const entry = store[key];
    if (entry && new Date(entry.expiresAt) < now) {
      delete store[key];
      removed++;
    }
  }
  if (removed > 0) scheduleFlush();
  return removed;
}

function evictOverflow(): void {
  const keys = Object.keys(store);
  if (keys.length <= MAX_ENTRIES) return;
  prune();
  const remaining = Object.entries(store);
  if (remaining.length <= MAX_ENTRIES) return;
  remaining
    .sort(([, a], [, b]) => a.expiresAt.localeCompare(b.expiresAt))
    .slice(0, remaining.length - MAX_ENTRIES)
    .forEach(([k]) => { delete store[k]; });
}

// Housekeeping: prune at startup and periodically; never keeps the process alive
prune();
setInterval(prune, PRUNE_INTERVAL_MS).unref();
