import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { PROVIDER_KEYS, config, reloadConfig } from './config.js';

describe('provider registry', () => {
  it('documents every provider key in .env.example', () => {
    const example = readFileSync(new URL('../.env.example', import.meta.url), 'utf8');
    const missing = PROVIDER_KEYS.filter(p => !new RegExp(`^${p.env}=`, 'm').test(example)).map(p => p.env);
    expect(missing).toEqual([]);
  });

  it('has unique providers and env vars', () => {
    expect(new Set(PROVIDER_KEYS.map(p => p.provider)).size).toBe(PROVIDER_KEYS.length);
    expect(new Set(PROVIDER_KEYS.map(p => p.env)).size).toBe(PROVIDER_KEYS.length);
  });

  it('reloads keys from the environment in place', () => {
    const providers = config.configuredProviders;
    const prev = process.env.SHODAN_API_KEY;
    process.env.SHODAN_API_KEY = 'test-key';
    reloadConfig();
    expect(config.shodan.apiKey).toBe('test-key');
    expect(config.configuredProviders).toBe(providers);
    expect(config.configuredProviders).toContain('shodan');

    process.env.SHODAN_API_KEY = '';
    reloadConfig();
    expect(config.configuredProviders).not.toContain('shodan');
    if (prev === undefined) delete process.env.SHODAN_API_KEY; else process.env.SHODAN_API_KEY = prev;
  });
});
