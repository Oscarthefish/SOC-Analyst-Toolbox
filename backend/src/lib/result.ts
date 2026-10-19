import type { EnrichmentResult } from '../types.js';

export function now(): string {
  return new Date().toISOString();
}

/**
 * Build a provider's result constructor: defaults for every EnrichmentResult field,
 * with the provider's id and name filled in. Adapters override what they know.
 */
export function resultFactory(providerId: string, providerName: string) {
  return (overrides: Partial<EnrichmentResult>): EnrichmentResult => ({
    providerId,
    providerName,
    status: 'ok',
    summary: '',
    severity: 'unknown',
    confidence: 'unknown',
    data: {},
    rawAvailable: false,
    checkedAt: now(),
    fromCache: false,
    ...overrides,
  });
}
