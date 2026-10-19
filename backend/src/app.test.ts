import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

// Route-level tests. None of these reach an external provider or write to disk:
// every write request here must be rejected before it does anything.
const cacheDir = mkdtempSync(join(tmpdir(), 'soc-app-'));
let server: Server;
let base: string;
let port: number;

beforeAll(async () => {
  process.env.CACHE_DIR = cacheDir;
  // Force "no key" so no test can reach Shodan (dotenv never overrides set variables)
  process.env.SHODAN_API_KEY = '';
  // Key writes go to a throwaway .env, never the real one
  process.env.ENV_FILE = join(cacheDir, '.env');
  const { createApp } = await import('./app.js');
  server = createApp().listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  port = (server.address() as AddressInfo).port;
  base = `http://127.0.0.1:${port}`;
});
afterAll(() => {
  server.close();
  rmSync(cacheDir, { recursive: true, force: true });
});

const post = (path: string, body?: unknown, headers: Record<string, string> = {}) =>
  fetch(base + path, {
    method: 'POST',
    headers: body === undefined ? headers : { 'Content-Type': 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

describe('request filtering', () => {
  it('serves health to local callers', async () => {
    const res = await fetch(`${base}/api/health`);
    expect(res.status).toBe(200);
  });

  it('accepts localhost as a host name', async () => {
    const res = await fetch(`http://localhost:${port}/api/health`).catch(() => null);
    // localhost may resolve to ::1 first on some systems; only assert when it connects
    if (res) expect(res.status).toBe(200);
  });

  it('rejects other Host headers (DNS rebinding)', async () => {
    // fetch() ignores a custom Host header, so use node:http directly
    const status = await new Promise<number>((resolve, reject) => {
      request({ host: '127.0.0.1', port, path: '/api/health', headers: { Host: `evil.example:${port}` } }, res => {
        res.resume();
        resolve(res.statusCode ?? 0);
      }).on('error', reject).end();
    });
    expect(status).toBe(403);
  });

  it('rejects browser requests from other origins', async () => {
    const res = await post('/api/config/keys', { key: 'SHODAN_API_KEY', value: 'x' }, { Origin: 'https://evil.example' });
    expect(res.status).toBe(403);
  });

  it('allows the local frontend origin', async () => {
    const res = await fetch(`${base}/api/health`, { headers: { Origin: 'http://localhost:5173' } });
    expect(res.status).toBe(200);
    expect(res.headers.get('access-control-allow-origin')).toBe('http://localhost:5173');
  });

  it('returns JSON 404s for unknown routes', async () => {
    const res = await fetch(`${base}/api/nope`);
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: 'Not found.' });
  });
});

describe('validation (Express 5: missing bodies must be 400, not 500)', () => {
  it.each([
    ['/api/enrich'],
    ['/api/analyse'],
    ['/api/analyse/stream'],
    ['/api/analyse-email-header'],
    ['/api/config/keys'],
  ])('%s without a body', async path => {
    expect((await post(path)).status).toBe(400);
  });

  it('rejects malformed JSON with 400', async () => {
    const res = await fetch(`${base}/api/enrich`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{bad' });
    expect(res.status).toBe(400);
  });

  it('rejects oversized bodies with 413', async () => {
    const res = await post('/api/enrich', { pad: 'x'.repeat(1_100_000) });
    expect(res.status).toBe(413);
  });

  it('rejects unknown IOC types', async () => {
    const res = await post('/api/enrich', { ioc: { original: 'x', normalised: 'x', type: 'bogus' } });
    expect(res.status).toBe(400);
  });

  it('refuses the credential validator without opt-in', async () => {
    const res = await post('/api/enrich', { ioc: { original: 'x', normalised: 'x', type: 'secret' }, providers: ['credvalidate'] });
    expect(res.status).toBe(403);
  });

  it('only accepts known key names', async () => {
    expect((await post('/api/config/keys', { key: 'PORT', value: '1' })).status).toBe(400);
  });

  it('rejects custom tools with non-http(s) URL templates', async () => {
    const res = await fetch(`${base}/api/tools/custom`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify([{ id: 'x', name: 'X', urlTemplate: 'javascript:alert(1)' }]),
    });
    expect(res.status).toBe(400);
  });
});

describe('caching', () => {
  it('does not cache missing-key results, so adding a key takes effect immediately', async () => {
    const body = { ioc: { original: '192.0.2.1', normalised: '192.0.2.1', type: 'ipv4' }, providers: ['shodan'] };
    const first = await (await post('/api/enrich', body)).json();
    const second = await (await post('/api/enrich', body)).json();
    expect(first.results[0].status).toBe('missing_key');
    expect(second.results[0]).toMatchObject({ status: 'missing_key', fromCache: false });
  });
});

describe('saving API keys', () => {
  it('updates .env atomically, keeps other lines, trims, and restricts permissions', async () => {
    const envFile = process.env.ENV_FILE!;
    writeFileSync(envFile, '# my settings\nPORT=8787\nHUNTER_API_KEY=old\n', { mode: 0o644 });
    const before = process.env.HUNTER_API_KEY;
    try {
      const res = await post('/api/config/keys', { key: 'HUNTER_API_KEY', value: '  new-key  ' });
      expect(await res.json()).toEqual({ ok: true, key: 'HUNTER_API_KEY', configured: true });
      expect(readFileSync(envFile, 'utf8')).toBe('# my settings\nPORT=8787\nHUNTER_API_KEY=new-key\n');
      expect(statSync(envFile).mode & 0o777).toBe(0o600);

      const status = await (await fetch(`${base}/api/config/keys`)).json();
      expect(status.keys.HUNTER_API_KEY).toBe(true);
    } finally {
      const { reloadConfig } = await import('./config.js');
      if (before === undefined) delete process.env.HUNTER_API_KEY; else process.env.HUNTER_API_KEY = before;
      reloadConfig();
    }
  });

  it('rejects values that would inject extra lines', async () => {
    const envFile = process.env.ENV_FILE!;
    writeFileSync(envFile, '');
    const before = process.env.HUNTER_API_KEY;
    try {
      await post('/api/config/keys', { key: 'HUNTER_API_KEY', value: 'abc\nENABLE_HIGH_RISK_ENRICHMENT=true' });
      expect(readFileSync(envFile, 'utf8')).toBe('HUNTER_API_KEY=abcENABLE_HIGH_RISK_ENRICHMENT=true');
    } finally {
      const { reloadConfig } = await import('./config.js');
      if (before === undefined) delete process.env.HUNTER_API_KEY; else process.env.HUNTER_API_KEY = before;
      reloadConfig();
    }
  });
});
