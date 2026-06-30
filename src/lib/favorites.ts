const STORAGE_KEY = 'soc-toolbox-favorites';

export function loadFavorites(): Set<string> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) return new Set(JSON.parse(raw) as string[]);
  } catch {
    // Storage may be unavailable or contain invalid JSON.
  }
  return new Set();
}

export function saveFavorites(favorites: Set<string>): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify([...favorites]));
  } catch {
    // Storage may be unavailable (for example, in private browsing mode).
  }
}
