import { describe, it, expect, beforeEach } from 'vitest';
import { installMemoryStorage } from '../test/memoryStorage';
import { STORAGE_KEYS, readList, writeJson, clearAllLocalData, storageUsage, isString } from './storage';
import { loadCases } from './cases';
import { loadHistory } from './searchHistory';
import { loadFavorites } from './favorites';

const store = installMemoryStorage();

describe('storage', () => {
  beforeEach(() => store.clear());

  it('reads only well-formed list items', () => {
    store.set(STORAGE_KEYS.favorites, JSON.stringify(['vt', 42, null, 'shodan']));
    expect(readList(STORAGE_KEYS.favorites, isString)).toEqual(['vt', 'shodan']);
  });

  it.each([
    ['not JSON', '{oops'],
    ['an object instead of a list', '{"a":1}'],
    ['a string', '"hello"'],
    ['null', 'null'],
  ])('treats %s as empty without throwing', (_label, raw) => {
    for (const key of Object.values(STORAGE_KEYS)) store.set(key, raw);
    expect(loadCases()).toEqual([]);
    expect(loadHistory()).toEqual([]);
    expect(loadFavorites().size).toBe(0);
  });

  it('drops malformed cases and history entries but keeps valid ones', () => {
    const goodCase = {
      id: '1', title: 'T', ticketRef: '', status: 'open', createdAt: '2026-01-01', updatedAt: '2026-01-01', notes: '',
      ioc: { original: 'x.com', normalised: 'x.com', type: 'domain' }, actionsTaken: [], checklist: {},
      workflowId: null, verdict: '', confidence: '', analysis: null,
    };
    store.set(STORAGE_KEYS.cases, JSON.stringify([goodCase, { id: 2 }, { ...goodCase, id: '3', ioc: null }]));
    expect(loadCases().map(c => c.id)).toEqual(['1']);

    store.set(STORAGE_KEYS.history, JSON.stringify([{ id: 'h', savedAt: 'now', ioc: { normalised: 'x', type: 'ipv4' } }]));
    expect(loadHistory()).toEqual([]); // no result → unusable entry
  });

  it('survives storage that throws', () => {
    const original = globalThis.localStorage;
    globalThis.localStorage = { getItem() { throw new Error('blocked'); }, setItem() { throw new Error('blocked'); }, removeItem() { throw new Error('blocked'); } } as unknown as Storage;
    try {
      expect(readList(STORAGE_KEYS.favorites, isString)).toEqual([]);
      expect(writeJson(STORAGE_KEYS.favorites, ['a'])).toBe(false);
      expect(() => clearAllLocalData()).not.toThrow();
    } finally {
      globalThis.localStorage = original;
    }
  });

  it('reports usage and clears only this app’s keys', () => {
    store.set(STORAGE_KEYS.cases, '[]');
    store.set('some-other-app', 'keep');
    expect(storageUsage().map(u => u.key)).toEqual([STORAGE_KEYS.cases]);
    clearAllLocalData();
    expect([...store.keys()]).toEqual(['some-other-app']);
  });
});
