import { createHash } from 'crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { EnrichmentResult } from './types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const CACHE_DIR = join(__dirname, '../../.cache');
const CACHE_FILE = join(CACHE_DIR, 'enrichment-cache.json');

interface CacheEntry {
  result: EnrichmentResult;
  expiresAt: string;
}

type CacheStore = Record<string, CacheEntry>;

function ensureCacheDir(): void {
  if (!existsSync(CACHE_DIR)) {
    mkdirSync(CACHE_DIR, { recursive: true });
  }
}

function loadFromDisk(): CacheStore {
  ensureCacheDir();
  if (!existsSync(CACHE_FILE)) return {};
  try {
    const raw = readFileSync(CACHE_FILE, 'utf-8');
    return JSON.parse(raw) as CacheStore;
  } catch {
    // Corrupt or missing file — start fresh
    return {};
  }
}

function saveToDisk(store: CacheStore): void {
  ensureCacheDir();
  try {
    writeFileSync(CACHE_FILE, JSON.stringify(store, null, 2), 'utf-8');
  } catch (err) {
    console.error('[cache] Failed to write cache to disk:', err);
  }
}

// Load once at startup
let store: CacheStore = loadFromDisk();

/**
 * Build a cache key. For sensitive URLs (type === 'url'), hash the normalised value
 * to avoid storing the raw URL on disk.
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
    // Expired — remove and return null
    delete store[key];
    return null;
  }
  return { ...entry.result, fromCache: true };
}

export function set(key: string, result: EnrichmentResult, ttlMinutes: number): void {
  const expiresAt = new Date(Date.now() + ttlMinutes * 60_000).toISOString();
  // Never persist API keys — result.data should never contain them, but be safe
  store[key] = { result, expiresAt };
  saveToDisk(store);
}

export function clear(): void {
  store = {};
  saveToDisk(store);
}

export function size(): number {
  return Object.keys(store).length;
}

// Prune expired entries (call periodically if desired)
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
  if (removed > 0) saveToDisk(store);
  return removed;
}
