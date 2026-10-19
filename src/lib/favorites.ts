import { STORAGE_KEYS, readList, writeJson, isString } from './storage';

export function loadFavorites(): Set<string> {
  return new Set(readList(STORAGE_KEYS.favorites, isString));
}

export function saveFavorites(favorites: Set<string>): void {
  writeJson(STORAGE_KEYS.favorites, [...favorites]);
}
