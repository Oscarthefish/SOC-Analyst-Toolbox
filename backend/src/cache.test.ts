import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { EnrichmentResult } from './types.js';

const dir = mkdtempSync(join(tmpdir(), 'soc-cache-'));
let cache: typeof import('./cache.js');

const result = (providerId: string): EnrichmentResult => ({
  providerId, providerName: providerId, status: 'ok', summary: '', severity: 'low',
  confidence: 'medium', data: {}, rawAvailable: false, checkedAt: '', fromCache: false,
});

beforeAll(async () => {
  process.env.CACHE_DIR = dir;
  cache = await import('./cache.js');
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe('cache', () => {
  it('returns stored results flagged as cached', () => {
    cache.set('a', result('vt'), 5);
    expect(cache.get('a')).toMatchObject({ providerId: 'vt', fromCache: true });
  });

  it('expires entries after their TTL', () => {
    cache.set('old', result('vt'), -1);
    expect(cache.get('old')).toBeNull();
  });

  it('hashes URLs and secrets in keys but not other types', () => {
    expect(cache.buildCacheKey('vt', 'ipv4', '8.8.8.8')).toBe('vt:ipv4:8.8.8.8');
    const url = cache.buildCacheKey('vt', 'url', 'https://x.test/?token=abc');
    const secret = cache.buildCacheKey('cv', 'secret', 'ghp_supersecret');
    expect(url).not.toContain('token');
    expect(secret).not.toContain('supersecret');
    expect(url).toMatch(/^vt:url:[0-9a-f]{16}$/);
  });

  it('coalesces writes into a single compact file', async () => {
    for (let i = 0; i < 50; i++) cache.set(`k${i}`, result('vt'), 5);
    await cache.flushNow();
    const raw = readFileSync(join(dir, 'enrichment-cache.json'), 'utf8');
    expect(raw).not.toContain('\n');
    expect(Object.keys(JSON.parse(raw))).toContain('k49');
  });

  it('prunes expired entries', () => {
    cache.set('stale', result('vt'), -1);
    expect(cache.prune()).toBeGreaterThanOrEqual(1);
  });

  it('caps the number of entries, evicting the soonest to expire', () => {
    cache.clear();
    cache.set('first', result('vt'), 1);
    for (let i = 0; i < 5_000; i++) cache.set(`bulk${i}`, result('vt'), 60);
    expect(cache.size()).toBe(5_000);
    expect(cache.get('first')).toBeNull();
  });
});
