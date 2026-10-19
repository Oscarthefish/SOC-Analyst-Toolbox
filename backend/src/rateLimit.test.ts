import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { acquire, markRateLimited, isRateLimited, limitFor, getRequestCount, resetRateLimits } from './rateLimit.js';

describe('rate limiting', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    resetRateLimits();
  });
  afterEach(() => {
    vi.useRealTimers();
    delete process.env.RATE_LIMIT_VIRUSTOTAL;
    delete process.env.RATE_LIMIT_CUSTOMPROV;
  });

  it('uses documented free-tier defaults and env overrides', () => {
    expect(limitFor('virustotal')).toBe(4);
    expect(limitFor('greynoise')).toBe(0);
    process.env.RATE_LIMIT_VIRUSTOTAL = '500';
    process.env.RATE_LIMIT_CUSTOMPROV = '7';
    expect(limitFor('virustotal')).toBe(500);
    expect(limitFor('customprov')).toBe(7);
  });

  it('never limits providers without a configured limit', async () => {
    for (let i = 0; i < 100; i++) expect(await acquire('greynoise', 0)).toBe(0);
  });

  it('allows the limit per minute, then reports how long to wait', async () => {
    for (let i = 0; i < 4; i++) expect(await acquire('virustotal', 0)).toBe(0);
    expect(getRequestCount('virustotal')).toBe(4);
    expect(isRateLimited('virustotal')).toBe(true);
    expect(await acquire('virustotal', 0)).toBe(60_000);
  });

  it('frees slots as the window slides', async () => {
    for (let i = 0; i < 4; i++) await acquire('virustotal', 0);
    vi.advanceTimersByTime(60_001);
    expect(await acquire('virustotal', 0)).toBe(0);
  });

  it('waits for a slot that opens within the allowed wait', async () => {
    for (let i = 0; i < 4; i++) await acquire('virustotal', 0);
    vi.advanceTimersByTime(55_000);
    const pending = acquire('virustotal', 10_000);
    await vi.advanceTimersByTimeAsync(5_000);
    await expect(pending).resolves.toBe(0);
  });

  it('pauses a provider for 60 s after a 429', async () => {
    markRateLimited('greynoise');
    expect(await acquire('greynoise', 0)).toBe(60_000);
    vi.advanceTimersByTime(60_000);
    expect(await acquire('greynoise', 0)).toBe(0);
  });
});
