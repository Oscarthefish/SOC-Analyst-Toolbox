import { describe, it, expect } from 'vitest';
import { toolFamily } from './toolFamily';

describe('toolFamily', () => {
  it('groups categories into families', () => {
    expect(toolFamily('Reputation')).toBe('intel');
    expect(toolFamily('Dark Web / Credential')).toBe('intel');
    expect(toolFamily('Malware / URL')).toBe('malware');
    expect(toolFamily('Phishing Reporting')).toBe('web');
    expect(toolFamily('Certificate / OSINT')).toBe('infra');
    expect(toolFamily('Business OSINT')).toBe('business');
    expect(toolFamily('Custom')).toBe('intel');
  });
});
