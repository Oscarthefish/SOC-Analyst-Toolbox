import type { AttackRef } from '../types.js';

const TECHNIQUE_ID = /^T\d{4}(?:\.\d{3})?$/;

/**
 * Normalise technique references from provider payloads: keep well-formed ids
 * only, upper-case them, strip a "T1234 - " prefix from names and de-duplicate.
 */
export function collectAttackRefs(items: { id?: unknown; name?: unknown }[], limit = 20): AttackRef[] {
  const out = new Map<string, AttackRef>();
  for (const item of items) {
    if (typeof item.id !== 'string') continue;
    const id = item.id.trim().toUpperCase();
    if (!TECHNIQUE_ID.test(id) || out.has(id)) continue;
    const name = typeof item.name === 'string'
      ? item.name.replace(/^T\d{4}(?:\.\d{3})?\s*[-:]\s*/i, '').trim()
      : '';
    out.set(id, name ? { id, name } : { id });
    if (out.size >= limit) break;
  }
  return [...out.values()];
}
