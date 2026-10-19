import { describe, it, expect, afterAll } from 'vitest';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { withDefaultUserAgent, withDeadline, USER_AGENT } from './http.js';

// A server that sends headers and part of the body, then stalls
const stalling = createServer((_req, res) => {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.write('{"partial":');
});
await new Promise<void>(resolve => stalling.listen(0, '127.0.0.1', resolve));
const stallUrl = `http://127.0.0.1:${(stalling.address() as AddressInfo).port}/`;
afterAll(() => { stalling.closeAllConnections(); stalling.close(); });

describe('withDefaultUserAgent', () => {
  it('adds a User-Agent when none is set, keeping other headers', () => {
    const h = new Headers(withDefaultUserAgent({ headers: { Accept: 'application/json' } }).headers);
    expect(h.get('User-Agent')).toBe(USER_AGENT);
    expect(h.get('Accept')).toBe('application/json');
  });

  it('keeps an explicit User-Agent', () => {
    const h = new Headers(withDefaultUserAgent({ headers: { 'user-agent': 'custom' } }).headers);
    expect(h.get('User-Agent')).toBe('custom');
  });

  it('preserves other request options', () => {
    const signal = new AbortController().signal;
    expect(withDefaultUserAgent({ method: 'POST', signal })).toMatchObject({ method: 'POST', signal });
  });
});

describe('withDeadline', () => {
  it('aborts a response whose body stalls after headers arrive', async () => {
    // Mimic an adapter: own timeout, cleared as soon as headers arrive
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5_000);
    const started = Date.now();
    const res = await fetch(stallUrl, withDeadline({ signal: controller.signal }, 300));
    clearTimeout(timer);
    await expect(res.text()).rejects.toThrow();
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  it("still honours the caller's own abort", async () => {
    const controller = new AbortController();
    const pending = fetch(stallUrl, withDeadline({ signal: controller.signal }, 10_000)).then(r => r.text());
    controller.abort();
    await expect(pending).rejects.toThrow();
  });
});
