/**
 * Everything the app keeps in localStorage, in one place.
 *
 * Reads never throw and never trust the stored shape: storage can be unavailable
 * (private browsing, blocked site data), corrupted, or written by an older version.
 * A bad value falls back to empty instead of crashing the app at startup.
 */

export const STORAGE_KEYS = {
  theme: 'theme',
  legacyDarkMode: 'dark-mode',
  recentIndicators: 'soc-toolbox-ioc-history',
  history: 'soc-toolbox-search-history',
  favorites: 'soc-toolbox-favorites',
  hiddenTools: 'soc-toolbox-hidden-tools',
  cases: 'soc-toolbox-cases-v2',
} as const;

export type StorageKey = (typeof STORAGE_KEYS)[keyof typeof STORAGE_KEYS];

/** Human-readable description of what each key holds (shown on the About page). */
export const STORAGE_DESCRIPTIONS: Record<StorageKey, string> = {
  'theme': 'Theme preference',
  'dark-mode': 'Theme preference (older format)',
  'soc-toolbox-ioc-history': 'Recently entered indicators',
  'soc-toolbox-search-history': 'Saved analyses (History)',
  'soc-toolbox-favorites': 'Pinned pivot tools',
  'soc-toolbox-hidden-tools': 'Hidden pivot tools',
  'soc-toolbox-cases-v2': 'Cases',
};

export function readRaw(key: StorageKey): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

/** Read a JSON array, keeping only items that pass `isItem`. Anything else reads as []. */
export function readList<T>(key: StorageKey, isItem: (x: unknown) => x is T): T[] {
  const raw = readRaw(key);
  if (!raw) return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter(isItem) : [];
  } catch {
    return [];
  }
}

/** Write JSON. Returns false if storage is unavailable or full. */
export function writeJson(key: StorageKey, value: unknown): boolean {
  try {
    localStorage.setItem(key, JSON.stringify(value));
    return true;
  } catch {
    return false;
  }
}

export function writeRaw(key: StorageKey, value: string): boolean {
  try {
    localStorage.setItem(key, value);
    return true;
  } catch {
    return false;
  }
}

export function removeKey(key: StorageKey): void {
  try {
    localStorage.removeItem(key);
  } catch { /* storage unavailable */ }
}

/** Approximate bytes used per key (UTF-16), for the About page. */
export function storageUsage(): { key: StorageKey; description: string; bytes: number }[] {
  return (Object.values(STORAGE_KEYS) as StorageKey[])
    .map(key => ({ key, description: STORAGE_DESCRIPTIONS[key], bytes: (readRaw(key)?.length ?? 0) * 2 }))
    .filter(u => u.bytes > 0);
}

/** Remove everything this app stores in the browser. */
export function clearAllLocalData(): void {
  for (const key of Object.values(STORAGE_KEYS)) removeKey(key);
}

// ── Shape guards ───────────────────────────────────────────────────────────

export const isString = (x: unknown): x is string => typeof x === 'string';

export function isRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}

/** True when `x` is an object whose listed fields are all strings. */
export function hasStringFields(x: unknown, fields: string[]): x is Record<string, unknown> {
  return isRecord(x) && fields.every(f => typeof x[f] === 'string');
}
