/** In-memory localStorage for tests running in Node. Returns the backing map. */
export function installMemoryStorage(): Map<string, string> {
  const store = new Map<string, string>();
  globalThis.localStorage = {
    getItem: k => store.get(k) ?? null,
    setItem: (k, v) => { store.set(k, String(v)); },
    removeItem: k => { store.delete(k); },
    clear: () => store.clear(),
    key: i => [...store.keys()][i] ?? null,
    get length() { return store.size; },
  } as Storage;
  return store;
}
